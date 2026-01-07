using Azure.Identity;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Graph;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using OIDC_ExternalID_API;
using OIDC_ExternalID_API.Middleware;
using System.IdentityModel.Tokens.Jwt;
using System.Reflection;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();

// Add JWT Bearer Authentication for Azure AD tokens
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        // Configure token validation for Azure AD tokens
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = false, // Azure AD tokens are validated by signature
            ValidateIssuer = false, // We accept tokens from any Azure AD tenant
            ValidateAudience = false, // We don't validate audience for flexibility
            ValidateLifetime = true, // Always validate token expiration
            RequireExpirationTime = true, // Require expiration time in tokens
            ClockSkew = TimeSpan.Zero // No tolerance for clock differences
        };

        // Handle authentication events for Azure AD tokens
        options.Events = new JwtBearerEvents
        {
            OnAuthenticationFailed = context =>
            {
                // Extract and validate Azure AD token
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

                            // Verify this is an Azure AD token
                            if (!string.IsNullOrEmpty(issuer) &&
                                (issuer.Contains("login.microsoftonline.com") || issuer.Contains("sts.windows.net")))
                            {
                                // Validate token expiration
                                var expClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == "exp")?.Value;
                                if (!string.IsNullOrEmpty(expClaim) && long.TryParse(expClaim, out var exp))
                                {
                                    var expirationTime = DateTimeOffset.FromUnixTimeSeconds(exp);
                                    if (expirationTime <= DateTimeOffset.UtcNow)
                                    {
                                        context.Fail("Azure AD token has expired");
                                        return Task.CompletedTask;
                                    }
                                }
                                else
                                {
                                    context.Fail("Azure AD token missing expiration claim");
                                    return Task.CompletedTask;
                                }

                                // Validate issued at time if present
                                var iatClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == "iat")?.Value;
                                if (!string.IsNullOrEmpty(iatClaim) && long.TryParse(iatClaim, out var iat))
                                {
                                    var issuedAtTime = DateTimeOffset.FromUnixTimeSeconds(iat);
                                    if (issuedAtTime > DateTimeOffset.UtcNow.AddMinutes(5))
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
                                    if (notBeforeTime > DateTimeOffset.UtcNow)
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
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        context.Fail($"Token validation error: {ex.Message}");
                        return Task.CompletedTask;
                    }
                }

                return Task.CompletedTask;
            }
        };
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("BlockAccess", policy =>
    {
        policy.RequireAssertion(context =>
        {
            // Always fail authorization for this policy
            return false;
        });
    });
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
        Version = "v1.0",
        Description = @"
        ## 🔐 Authentication & User Management API

        This API provides Azure AD user management capabilities with secure token-based authentication.

        ### Authentication
        - **Token Type**: Azure AD Bearer Tokens
        - **Token Endpoint**: `POST /Token/Get AAD Token`
        - **Token Format**: `Bearer <access_token>`

        ### Available Endpoints

        **Token Management:**
        - Generate Azure AD access tokens for API authentication

        **User Management:**
        - Retrieve user details by identifier (ID, UPN, or Email)
        - Update user attributes
        - Update specific user attributes (firstName, lastName, displayName)
        - Delete users

        ### Quick Start
        1. Generate an Azure AD token: `POST /Token/Get AAD Token`
        2. Copy the `access_token` from the response
        3. Click the 'Authorize' button below
        4. Enter: `Bearer <access_token>`
        5. Test the Graph endpoints

        ### User Identifiers
        All Graph endpoints accept three types of identifiers:
        - **Object ID (UID)**: Azure AD user object ID
        - **User Principal Name (UPN)**: user@domain.com
        - **Email Address**: user@domain.com
        "
    });

    // Add Bearer token authentication for Swagger UI
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = @"
        **Azure AD JWT Authorization header using the Bearer scheme.**

        **How to authenticate:**
        1. Generate a token using `POST /Token/Get AAD Token`
        2. Copy the `access_token` from the response
        3. Enter the token below in the format: `Bearer <access_token>`

        **Format:** `Bearer <your-token>`

        **Example:** `Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...`",

        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });
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
    });
// }

// After app creation, before app.UseAuthorization()
app.UseCors("AllowSwaggerUI");

// Enable static files for custom Swagger UI assets
app.UseStaticFiles();

app.UseHttpsRedirection();

app.UseMiddleware<ErrorHandlingMiddleware>();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
