// Custom Swagger UI JavaScript Enhancements

(function() {
    'use strict';

    // Wait for Swagger UI to load
    function waitForSwaggerUI() {
        if (typeof SwaggerUIBundle !== 'undefined') {
            initializeCustomFeatures();
        } else {
            setTimeout(waitForSwaggerUI, 100);
        }
    }

    function initializeCustomFeatures() {
        console.log('Initializing custom Swagger UI features...');
        
        // Add custom features after Swagger UI loads
        setTimeout(() => {
            addTokenGenerationHelper();
            addTokenTimerToAuthSection(); // Add token timer to auth section instead of copy button
            addQuickTestButtons();
            addEnhancedStyling();
            addKeyboardShortcuts();
        }, 1000);
    }

    // Add token generation helper
    function addTokenGenerationHelper() {
        const authSection = document.querySelector('.auth-wrapper');
        if (!authSection) return;

        const helperDiv = document.createElement('div');
        helperDiv.className = 'token-helper';
        // The following block is commented out to disable the Quick Token Generation box:
        /*
        helperDiv.innerHTML = `
            <div style="margin: 10px 0; padding: 15px; background: #f8f9fa; border-radius: 4px; border-left: 4px solid #667eea;">
                <h4 style="margin: 0 0 10px 0; color: #3b4151;">🔑 Quick Token Generation</h4>
                <p style="margin: 0 0 10px 0; color: #555; font-size: 14px;">
                    Need a token? Use one of these endpoints:
                </p>
                <div style="display: flex; gap: 10px; flex-wrap: wrap;">
                    <button onclick="generateToken('azure-ad')" style="background: #49cc90; color: white; border: none; padding: 8px 12px; border-radius: 4px; cursor: pointer; font-size: 12px;">
                        Generate Azure AD Token
                    </button>
                    <button onclick="generateToken('custom')" style="background: #667eea; color: white; border: none; padding: 8px 12px; border-radius: 4px; cursor: pointer; font-size: 12px;">
                        Generate Custom JWT
                    </button>
                </div>
            </div>
        `;
        */
        authSection.parentNode.insertBefore(helperDiv, authSection);
    }

    // Add token timer to auth section (replacing copy token button)
    function addTokenTimerToAuthSection() {
        const authorizeBtn = document.querySelector('.auth-wrapper .authorize');
        if (!authorizeBtn) return;

        // Create timer container to replace copy button
        const timerContainer = document.createElement('div');
        timerContainer.id = 'auth-token-timer';
        timerContainer.style.cssText = `
            display: inline-block;
            margin-left: 10px;
            vertical-align: middle;
        `;
        timerContainer.innerHTML = `
            <div id="timer-display" style="display: inline-block; background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 4px; padding: 8px 12px; font-size: 12px; min-width: 120px; text-align: center;">
                <span id="time-remaining">⏳ Ready</span>
            </div>
            <button id="refresh-token-btn" style="background: #667eea; color: white; border: none; padding: 8px 12px; border-radius: 4px; cursor: pointer; font-size: 12px; margin-left: 5px; display: none;">
                🔄 New Token
            </button>
        `;
        
        // Insert timer container after authorize button
        authorizeBtn.parentNode.appendChild(timerContainer);
        
        // Add event listeners
        document.getElementById('refresh-token-btn').addEventListener('click', () => {
            openTokenGenerationEndpoint();
        });
        
        // Monitor for token changes
        monitorTokenChanges();
    }

    // Add quick test buttons
    function addQuickTestButtons() {
        const opblocks = document.querySelectorAll('.opblock');
        
        opblocks.forEach(opblock => {
            const summary = opblock.querySelector('.opblock-summary');
            if (!summary) return;

            const testBtn = document.createElement('button');
            testBtn.className = 'quick-test-btn';
            testBtn.innerHTML = '🧪 Quick Test';
            testBtn.style.cssText = `
                background: #ffc107;
                color: #212529;
                border: none;
                padding: 4px 8px;
                border-radius: 4px;
                cursor: pointer;
                font-size: 11px;
                margin-left: 10px;
            `;
            
            testBtn.onclick = function(e) {
                e.stopPropagation();
                const executeBtn = opblock.querySelector('.btn.execute');
                if (executeBtn) {
                    executeBtn.click();
                }
            };

            summary.appendChild(testBtn);
        });
    }

    // Add enhanced styling
    function addEnhancedStyling() {
        const style = document.createElement('style');
        style.textContent = `
            .token-helper {
                margin: 15px 0;
            }
            
            .quick-test-btn:hover {
                background: #e0a800 !important;
                transform: translateY(-1px);
            }
            
            .opblock-summary:hover {
                background: rgba(0,0,0,0.02);
            }
            
            .swagger-ui .opblock-description {
                background: #f8f9fa;
                padding: 15px;
                border-radius: 4px;
                margin: 10px 0;
                border-left: 4px solid #667eea;
            }
            
            .swagger-ui .responses-wrapper {
                background: #f8f9fa;
                border-radius: 4px;
                padding: 15px;
                margin: 10px 0;
            }
            
            .swagger-ui .responses-table {
                background: white;
                border-radius: 4px;
                overflow: hidden;
            }
            
            #auth-token-timer.warning #time-remaining {
                color: #e07c00;
                font-weight: bold;
            }
            
            #auth-token-timer.expired #time-remaining {
                color: #e02d2d;
                font-weight: bold;
            }
            
            #auth-token-timer.expired #refresh-token-btn {
                background: #e02d2d !important;
                display: inline-block !important;
            }
        `;
        document.head.appendChild(style);
    }

    // Add keyboard shortcuts
    function addKeyboardShortcuts() {
        document.addEventListener('keydown', function(e) {
            // Ctrl/Cmd + K to focus on authorization
            if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
                e.preventDefault();
                const authInput = document.querySelector('.auth-wrapper input[type="text"]');
                if (authInput) {
                    authInput.focus();
                }
            }
            
            // Ctrl/Cmd + Enter to execute current operation
            if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                const activeExecuteBtn = document.querySelector('.opblock.is-open .btn.execute');
                if (activeExecuteBtn) {
                    activeExecuteBtn.click();
                }
            }
        });
    }

    // Monitor for token changes in the authorization input
    function monitorTokenChanges() {
        let lastToken = '';
        let tokenDetected = false;
        
        const checkToken = () => {
            try {
                // Check for token in authorization modal input
                const modalInput = document.querySelector('.dialog-ux .modal-ux-content input[type="text"]');
                if (modalInput && modalInput.value && modalInput.value !== lastToken) {
                    lastToken = modalInput.value;
                    if (!tokenDetected) {
                        console.log('Token detected in modal input');
                        startTokenTimer(3600); // Start 60-minute timer
                        tokenDetected = true;
                    }
                    return;
                }
                
                // Check for token in locked authorization view
                const lockedAuth = document.querySelector('.auth-wrapper .auth-container');
                if (lockedAuth) {
                    const codeElements = lockedAuth.querySelectorAll('code');
                    for (let i = 0; i < codeElements.length; i++) {
                        const text = codeElements[i].textContent || codeElements[i].innerText;
                        if (text && text !== lastToken && (text.startsWith('Bearer ') || text.includes('.'))) {
                            lastToken = text;
                            if (!tokenDetected) {
                                console.log('Token detected in locked auth view');
                                startTokenTimer(3600); // Start 60-minute timer
                                tokenDetected = true;
                            }
                            return;
                        }
                    }
                }
                
                // Check for token in authorize button state
                const authorizeBtn = document.querySelector('.auth-wrapper .authorize');
                if (authorizeBtn && authorizeBtn.textContent.includes('Logout')) {
                    // User is authenticated
                    if (!tokenDetected) {
                        console.log('User authenticated, starting 60-minute timer');
                        startTokenTimer(3600); // Start 60-minute timer
                        tokenDetected = true;
                    }
                } else {
                    // User is not authenticated
                    if (tokenDetected) {
                        console.log('User logged out, stopping timer');
                        stopTokenTimer();
                        tokenDetected = false;
                    }
                }
            } catch (e) {
                console.error('Error monitoring token changes:', e);
            }
            
            setTimeout(checkToken, 2000); // Check every 2 seconds
        };
        
        checkToken();
    }

    // Timer variables
    let tokenTimerInterval = null;

    // Start token timer
    function startTokenTimer(durationSeconds) {
        // Stop any existing timer
        stopTokenTimer();
        
        const timerContainer = document.getElementById('auth-token-timer');
        const timeRemaining = document.getElementById('time-remaining');
        const refreshTokenBtn = document.getElementById('refresh-token-btn');
        
        // Reset styles
        timerContainer.classList.remove('warning', 'expired');
        refreshTokenBtn.style.display = 'none';
        
        // Start with the full duration
        let remainingTime = durationSeconds;
        
        const updateTimer = () => {
            // If token has expired
            if (remainingTime <= 0) {
                timeRemaining.textContent = 'EXPIRED!';
                timerContainer.classList.add('expired');
                refreshTokenBtn.style.display = 'inline-block';
                return;
            }
            
            // Calculate hours, minutes, seconds
            const hours = Math.floor(remainingTime / 3600);
            const minutes = Math.floor((remainingTime % 3600) / 60);
            const seconds = remainingTime % 60;
            
            // Update display
            if (hours > 0) {
                timeRemaining.textContent = `${hours}h ${minutes}m`;
            } else if (minutes > 0) {
                timeRemaining.textContent = `${minutes}m ${seconds}s`;
            } else {
                timeRemaining.textContent = `${seconds}s`;
            }
            
            // Show warning when less than 5 minutes remaining
            if (remainingTime < 300) { // 5 minutes
                timerContainer.classList.add('warning');
            }
            
            // Show refresh button when less than 1 minute remaining
            if (remainingTime < 60) { // 1 minute
                refreshTokenBtn.style.display = 'inline-block';
            }
            
            // Decrement remaining time
            remainingTime--;
        };
        
        // Initial update
        updateTimer();
        
        // Start the interval
        tokenTimerInterval = setInterval(updateTimer, 1000);
    }

    // Stop token timer
    function stopTokenTimer() {
        if (tokenTimerInterval) {
            clearInterval(tokenTimerInterval);
            tokenTimerInterval = null;
        }
        
        // Reset timer display
        const timeRemaining = document.getElementById('time-remaining');
        if (timeRemaining) {
            timeRemaining.textContent = '⏳ Ready';
        }
        
        // Hide refresh button
        const refreshTokenBtn = document.getElementById('refresh-token-btn');
        if (refreshTokenBtn) {
            refreshTokenBtn.style.display = 'none';
        }
        
        // Remove styling classes
        const timerContainer = document.getElementById('auth-token-timer');
        if (timerContainer) {
            timerContainer.classList.remove('warning', 'expired');
        }
    }

    // Open the token generation endpoint in Swagger UI
    function openTokenGenerationEndpoint() {
        try {
            console.log('Opening token generation endpoint');
            
            // Close the authorization modal if it's open
            const closeBtn = document.querySelector('.auth-btn-wrapper .btn-done');
            if (closeBtn) {
                closeBtn.click();
            }
            
            // Find and click the "Token" controller section
            const tokenSections = document.querySelectorAll('.opblock-tag[data-tag="Token"]');
            console.log('Found', tokenSections.length, 'Token sections');
            
            if (tokenSections.length > 0) {
                const tokenSection = tokenSections[0];
                
                // Expand the section if it's collapsed
                const collapseButton = tokenSection.querySelector('.expand-operation');
                if (collapseButton) {
                    // Check if it's already expanded
                    const isExpanded = collapseButton.getAttribute('aria-expanded') === 'true';
                    console.log('Collapse button is expanded:', isExpanded);
                    if (!isExpanded) {
                        collapseButton.click();
                        console.log('Clicked collapse button');
                    }
                }
                
                // Find the Get AAD Token endpoint specifically
                const getAadTokenEndpoints = tokenSection.parentElement.querySelectorAll('.opblock-summary[method="POST"]');
                console.log('Found', getAadTokenEndpoints.length, 'POST endpoints');
                
                for (let i = 0; i < getAadTokenEndpoints.length; i++) {
                    const endpoint = getAadTokenEndpoints[i];
                    const pathEl = endpoint.querySelector('.opblock-summary-path');
                    if (pathEl) {
                        const pathText = pathEl.textContent;
                        console.log('Endpoint path:', pathText);
                        if (pathText && pathText.includes('Get AAD Token')) {
                            console.log('Found Get AAD Token endpoint');
                            // Scroll to the endpoint
                            endpoint.scrollIntoView({ behavior: 'smooth', block: 'center' });
                            
                            // Highlight the endpoint briefly
                            endpoint.style.backgroundColor = '#ffffcc';
                            setTimeout(() => {
                                endpoint.style.backgroundColor = '';
                            }, 2000);
                            break;
                        }
                    }
                }
            } else {
                console.log('Token section not found');
            }
        } catch (e) {
            console.error('Error opening token generation endpoint:', e);
        }
    }

    // Global functions for token generation
    window.generateToken = function(type) {
        const baseUrl = window.location.origin;
        let endpoint, requestBody;
        
        if (type === 'azure-ad') {
            endpoint = '/Token/azure-ad';
            requestBody = {
                client_id: 'your-client-id',
                client_secret: 'your-client-secret',
                scope: 'https://graph.microsoft.com/.default'
            };
        } else if (type === 'custom') {
            endpoint = '/Token';
            requestBody = new FormData();
            requestBody.append('client_id', 'your-client-id');
            requestBody.append('client_secret', 'your-client-secret');
            requestBody.append('scope', 'api://default');
            requestBody.append('grant_type', 'client_credentials');
        }
        
        // Show a modal with the request details
        showTokenGenerationModal(type, endpoint, requestBody);
    };

    function showTokenGenerationModal(type, endpoint, requestBody) {
        const modal = document.createElement('div');
        modal.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.5);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 10000;
        `;
        
        const content = document.createElement('div');
        content.style.cssText = `
            background: white;
            padding: 30px;
            border-radius: 8px;
            max-width: 600px;
            width: 90%;
            max-height: 80vh;
            overflow-y: auto;
        `;
        
        const isFormData = requestBody instanceof FormData;
        const requestBodyText = isFormData ? 
            Array.from(requestBody.entries()).map(([key, value]) => `${key}: ${value}`).join('\n') :
            JSON.stringify(requestBody, null, 2);
        
        content.innerHTML = `
            <h3 style="margin: 0 0 20px 0; color: #3b4151;">Generate ${type === 'azure-ad' ? 'Azure AD' : 'Custom JWT'} Token</h3>
            <p style="color: #555; margin-bottom: 20px;">
                Use this endpoint to generate a token, then copy the <code>access_token</code> from the response.
            </p>
            
            <div style="margin-bottom: 20px;">
                <strong>Endpoint:</strong>
                <code style="background: #f8f9fa; padding: 5px 10px; border-radius: 4px; display: block; margin-top: 5px;">
                    POST ${window.location.origin}${endpoint}
                </code>
            </div>
            
            <div style="margin-bottom: 20px;">
                <strong>Request Body:</strong>
                <pre style="background: #f8f9fa; padding: 15px; border-radius: 4px; overflow-x: auto; margin-top: 5px;">${requestBodyText}</pre>
            </div>
            
            <div style="margin-bottom: 20px;">
                <strong>Steps:</strong>
                <ol style="margin: 10px 0; padding-left: 20px;">
                    <li>Update the <code>client_id</code> and <code>client_secret</code> with your actual values</li>
                    <li>Send the request to the endpoint</li>
                    <li>Copy the <code>access_token</code> from the response</li>
                    <li>Click "Authorize" in Swagger UI and paste the token</li>
                </ol>
            </div>
            
            <div style="text-align: right;">
                <button onclick="this.closest('.modal').remove()" style="background: #6c757d; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer;">
                    Close
                </button>
            </div>
        `;
        
        modal.appendChild(content);
        modal.className = 'modal';
        document.body.appendChild(modal);
        
        // Close modal when clicking outside
        modal.addEventListener('click', function(e) {
            if (e.target === modal) {
                modal.remove();
            }
        });
    }

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', waitForSwaggerUI);
    } else {
        waitForSwaggerUI();
    }

})();