using Azure.Identity;
using Microsoft.AspNetCore.Builder;
using Microsoft.Graph;
using Microsoft.OpenApi.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using System.Reflection;
using Microsoft.OpenApi.Any;
using OIDC_ExternalID_API;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();

// Add JWT Bearer Authentication with support for both custom JWT and Azure AD tokens
var jwtSecret = builder.Configuration["Jwt:Secret"];
if (string.IsNullOrEmpty(jwtSecret))
{
    // Generate a random secret if not configured
    using var rng = new System.Security.Cryptography.RNGCryptoServiceProvider();
    var bytes = new byte[32];
    rng.GetBytes(bytes);
    jwtSecret = Convert.ToBase64String(bytes);
}

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(jwtSecret)),
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = true, // Enable lifetime validation for custom JWT tokens
            RequireExpirationTime = true, // Require expiration time in tokens
            ClockSkew = TimeSpan.Zero // No tolerance for clock differences
        };
        
        // Handle authentication events to support Azure AD tokens
        options.Events = new JwtBearerEvents
        {
            OnTokenValidated = context =>
            {
                // If token validation succeeded, we're good
                return Task.CompletedTask;
            },
            OnAuthenticationFailed = context =>
            {
                // Check if this might be an Azure AD token
                var token = context.Request.Headers["Authorization"].FirstOrDefault()?.Replace("Bearer ", "");
                if (!string.IsNullOrEmpty(token))
                {
                    try
                    {
                        var tokenHandler = new JwtSecurityTokenHandler();
                        if (tokenHandler.CanReadToken(token))
                        {
                            var jwtToken = tokenHandler.ReadJwtToken(token);
                            var issuer = jwtToken.Claims.FirstOrDefault(c => c.Type == "iss")?.Value;

                            // If it's an Azure AD token, don't fail authentication, validate expiration before accepting
                            if (!string.IsNullOrEmpty(issuer) && 
                                (issuer.Contains("login.microsoftonline.com") || issuer.Contains("sts.windows.net")))
                            {



                                // Validate token expiration for Azure AD tokens
                                var expClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == "exp")?.Value;
                                if (!string.IsNullOrEmpty(expClaim) && long.TryParse(expClaim, out var exp))
                                {
                                    var expirationTime = DateTimeOffset.FromUnixTimeSeconds(exp);
                                    var currentTime = DateTimeOffset.UtcNow;

                                    // Check if token has expired (with no clock skew tolerance)
                                    if (expirationTime <= currentTime)
                                    {
                                        context.Fail("Azure AD token has expired");
                                        return Task.CompletedTask;
                                    }
                                }
                                else
                                {
                                    // No expiration claim found - reject the token
                                    context.Fail("Azure AD token missing expiration claim");
                                    return Task.CompletedTask;
                                }





                                // Validate issued at time if present
                                var iatClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == "iat")?.Value;
                                if (!string.IsNullOrEmpty(iatClaim) && long.TryParse(iatClaim, out var iat))
                                {
                                    var issuedAtTime = DateTimeOffset.FromUnixTimeSeconds(iat);
                                    var currentTime = DateTimeOffset.UtcNow;

                                    // Reject tokens issued in the future (clock skew protection)
                                    if (issuedAtTime > currentTime.AddMinutes(5)) // Allow 5 minutes clock skew
                                    {
                                        context.Fail("Azure AD token issued in the future");
                                        return Task.CompletedTask;
                                    }
                                }





                                // Validate not before time if present
                                var nbfClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == "nbf")?.Value;
                                if (!string.IsNullOrEmpty(nbfClaim) && long.TryParse(nbfClaim, out var nbf))
                                {
                                    var notBeforeTime = DateTimeOffset.FromUnixTimeSeconds(nbf);
                                    var currentTime = DateTimeOffset.UtcNow;

                                    // Check if token is not yet valid
                                    if (notBeforeTime > currentTime)
                                    {
                                        context.Fail("Azure AD token not yet valid");
                                        return Task.CompletedTask;
                                    }
                                }

                                // Token is valid - create claims principal
                                var claims = jwtToken.Claims.Select(c => new System.Security.Claims.Claim(c.Type, c.Value)).ToList();
                                var identity = new System.Security.Claims.ClaimsIdentity(claims, "Bearer");
                                var principal = new System.Security.Claims.ClaimsPrincipal(identity);

                                context.Principal = principal;
                                context.Success();
                                return Task.CompletedTask;


                                // Create a claims principal for the Azure AD token
                                //var claims = jwtToken.Claims.Select(c => new System.Security.Claims.Claim(c.Type, c.Value)).ToList();
                                //var identity = new System.Security.Claims.ClaimsIdentity(claims, "Bearer");
                                //var principal = new System.Security.Claims.ClaimsPrincipal(identity);
                                
                                //context.Principal = principal;
                                //context.Success();
                                //return Task.CompletedTask;
                            }
                        }
                    }
                    catch(Exception ex)
                    {
                        // If we can't parse the token, let it fail normally
                        // Log the exception for debugging
                        context.Fail($"Token validation error: {ex.Message}");
                        return Task.CompletedTask;
                    }
                }
                
                // Let the authentication fail normally for other cases
                return Task.CompletedTask;
            }
        };
    });

builder.Services.AddAuthorization();

// Add session support for OAuth 2.0 authorization code flow
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(30);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});

// Add the Graph API client
var scopes = new[] { "https://graph.microsoft.com/.default" };
var tenantId = builder.Configuration["AzureAd:TenantId"];
var clientId = builder.Configuration["AzureAd:ClientId"];
var clientSecret = builder.Configuration["AzureAd:ClientSecret"];

var clientSecretCredential = new ClientSecretCredential(tenantId, clientId, clientSecret);

builder.Services.AddSingleton(new GraphServiceClient(clientSecretCredential, scopes));

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo 
    { 
        Title = "External ID Graph API", 
        Version = "v1",
        Description = @"
        ## 🔐 Authentication System

        This API supports multiple authentication methods:

        ### Token Types Supported:        
        1. **Azure AD Tokens** (from `/Token/azure-ad` endpoint)

        ### How to Use:
        1. **Generate a token** using one of the Token endpoints
        2. **Click 'Authorize'** in Swagger UI
        3. **Enter your token** in format: `Bearer <your-token>`
        4. **Test the endpoints** - token will be automatically included

        ### Supported Controllers:
        - **TokenController**: Generate and validate tokens
        - **GraphController**: Azure AD user management (uses GraphServiceClient)
        - **CustomGraphController**: Direct Microsoft Graph API calls

        ### Quick Start:
        1. Generate token: `POST /Token/azure-ad` or `POST /Token`
        2. Copy the `access_token` from response
        3. Click 'Authorize' and enter: `Bearer <access_token>`
        4. Test endpoints like `GET /CustomGraph/getUserByEmail`
        ",
        // ### Token Types Supported:  1. **Custom JWT Tokens** (from `/Token` endpoint)
        // ### Quick Start: For detailed documentation, see the [Azure AD Token Usage Guide](AZURE_AD_TOKEN_USAGE.md).
        //Contact = new OpenApiContact
        //{
        //    Name = "API Support",
        //    Email = "support@example.com"
        //},
        //License = new OpenApiLicense
        //{
        //    Name = "MIT License",
        //    Url = new Uri("https://opensource.org/licenses/MIT")
        //}
    });
    //### Token Types Supported: 3. **Azure AD Client Credentials** (from `/Token/azure-ad/client-credentials` endpoint)

    // Add Bearer token authentication for Swagger UI
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = @"
        **JWT Authorization header using the Bearer scheme.**

        **Supported Token Types:**
        - Custom JWT tokens (from `/Token`)
        - Azure AD tokens (from `/Token/azure-ad`)
       

        **Format:** `Bearer <your-token>`

        **Example:** `Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...`",

        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });
    // **Supported Token Types:** - Azure AD client credentials (from `/Token/azure-ad/client-credentials`)
    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            new string[] {}
        }
    });

    // Add operation filters for better documentation
    c.OperationFilter<SwaggerDefaultValues>();
    
    // Add schema filters for better model documentation
    c.SchemaFilter<SwaggerSchemaFilter>();
    
    // Include XML comments if available
    var xmlFile = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
    var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
    if (File.Exists(xmlPath))
    {
        c.IncludeXmlComments(xmlPath);
    }

    // Group operations by controller
    c.TagActionsBy(api =>
    {
        if (api.GroupName != null)
        {
            return new[] { api.GroupName.ToString() };
        }

        var controllerActionDescriptor = api.ActionDescriptor as Microsoft.AspNetCore.Mvc.Controllers.ControllerActionDescriptor;
        if (controllerActionDescriptor != null)
        {
            return new[] { controllerActionDescriptor.ControllerName };
        }

        throw new InvalidOperationException("Unable to determine tag for endpoint.");
    });

    c.DocInclusionPredicate((name, api) => true);

    // // OAuth2 Authorization Code flow for Azure AD with PKCE (any Microsoft user)
    // c.AddSecurityDefinition("oauth2", new OpenApiSecurityScheme
    // {
    //     Type = SecuritySchemeType.OAuth2,
    //     Flows = new OpenApiOAuthFlows
    //     {
    //         AuthorizationCode = new OpenApiOAuthFlow
    //         {
    //             AuthorizationUrl = new Uri("https://login.microsoftonline.com/volvogroupextid.onmicrosoft.com/oauth2/v2.0/authorize"),
    //             TokenUrl = new Uri("https://login.microsoftonline.com/volvogroupextid.onmicrosoft.com/oauth2/v2.0/token"),
    //             //AuthorizationUrl = new Uri("https://login.microsoftonline.com/common/oauth2/v2.0/authorize"),
    //             //TokenUrl = new Uri("https://login.microsoftonline.com/common/oauth2/v2.0/token"),
    //             Scopes = new Dictionary<string, string>
    //             {
    //                 { "User.Read.All", "Read all users' full profiles" },
    //                 { "User.ReadWrite.All", "Read and write all users' full profiles" },
    //                 { "Directory.AccessAsUser.All", "Access directory as the signed-in user" },
    //                 { "offline_access", "Maintain access to data you have given it access to" },
    //                 { "openid", "Sign users in" }
    //             }
    //         }
    //     }
    // });
    // c.AddSecurityRequirement(new OpenApiSecurityRequirement
    // {
    //     {
    //         new OpenApiSecurityScheme
    //         {
    //             Reference = new OpenApiReference
    //             {
    //                 Type = ReferenceType.SecurityScheme,
    //                 Id = "oauth2"
    //             }
    //         },
    //         new[] { "User.Read.All", "User.ReadWrite.All", "Directory.AccessAsUser.All", "offline_access", "openid" }
    //     }
    // });

    // Read the README.md file
    //var readmeText = File.ReadAllText("README.md");
    //c.SwaggerDoc("v1", new OpenApiInfo
    //{
    //    Title = "External ID Graph Api",
    //    Version = "v1",
    //    Description = readmeText // This will show your README in Swagger UI
    //});

});

// Add this before builder.Build()
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowSwaggerUI", policy =>
    {
        policy
            //https://localhost:7110
            .WithOrigins("https://localhost:7110", 
            "https://externalid-restapi-hcbvbpeef6c8gbay.southeastasia-01.azurewebsites.net"
            ) // <-- Replace with your Swagger UI origin
            //.AllowAnyOrigin()
            .AllowAnyHeader()
            .AllowAnyMethod();
    });
});

builder.Services.AddHttpClient();
builder.Services.AddHttpContextAccessor();

var app = builder.Build();

// Configure the HTTP request pipeline.
// if (app.Environment.IsDevelopment())
// {
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "External ID Graph API v1");
        c.RoutePrefix = "swagger";
        
        // Enhanced UI configuration
        c.DocumentTitle = "External ID Graph API Documentation";
        c.DefaultModelsExpandDepth(-1);
        c.DefaultModelExpandDepth(2);
        c.DisplayRequestDuration();
        c.DocExpansion(Swashbuckle.AspNetCore.SwaggerUI.DocExpansion.List);
        c.EnableDeepLinking();
        c.EnableFilter();
        c.ShowExtensions();
        c.ShowCommonExtensions();
        
        // Custom CSS for better styling
        c.InjectStylesheet("/swagger-ui/custom.css");
        
        // Custom JavaScript for enhanced functionality
        c.InjectJavascript("/swagger-ui/custom.js");
        
        // OAuth2 configuration (commented out for now)
        // c.OAuthClientId("your-client-id");
        // c.OAuthScopes("User.Read.All", "User.ReadWrite.All", "Directory.AccessAsUser.All", "offline_access", "openid");
        // c.OAuthUsePkce();
        // c.OAuth2RedirectUrl("https://externalid-restapi-hcbvbpeef6c8gbay.southeastasia-01.azurewebsites.net/swagger/oauth2-redirect.html");
    });
// }

// After app creation, before app.UseAuthorization()
app.UseCors("AllowSwaggerUI");

// Enable static files for custom Swagger UI assets
app.UseStaticFiles();

app.UseHttpsRedirection();

// Add session middleware
app.UseSession();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
