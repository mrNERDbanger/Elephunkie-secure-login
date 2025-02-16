jQuery(document).ready(function($) {
    function attemptLogin() {
        $.ajax({
            url: secureAutoLogin.ajax_url,
            type: 'POST',
            data: {
                action: 'secure_auto_login',
                nonce: secureAutoLogin.nonce
            },
            success: function(response) {
                if (response.success) {
                    if (response.data.verification_needed) {
                        showEmailVerificationForm(response.data.users);
                    } else if (response.data.admin_bar) {
                        // Update admin bar without page reload
                        $('#wpadminbar').remove();
                        $('body').prepend(response.data.admin_bar);
                        $('html').addClass('wp-toolbar');
                        // Update any login-dependent elements
                        $('.logged-out').hide();
                        $('.logged-in').show();
                    }
                }
            }
        });
    }

    function showEmailVerificationForm(users) {
        // Remove any existing modal
        $('#secure-login-modal').remove();
        
        // Create modal HTML that looks like WP login
        var modal = $(`
            <div id="secure-login-modal" style="
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0,0,0,0.8);
                display: flex;
                align-items: center;
                justify-content: center;
                z-index: 999999;
            ">
                <div id="login" style="
                    background: #fff;
                    padding: 24px;
                    border-radius: 4px;
                    max-width: 320px;
                    width: 90%;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.2);
                ">
                    <h1>
                        <a href="${secureAutoLogin.site_url}">
                            <img src="${secureAutoLogin.wp_logo}" alt="WordPress" width="84" height="84">
                        </a>
                    </h1>
                    <p class="message">Multiple users detected for this IP address. Please verify your email to continue.</p>
                    <form id="email-verify-form">
                        <p>
                            <label for="user-email">Email Address</label>
                            <input type="email" name="user-email" id="user-email" class="input" required>
                        </p>
                        <p class="submit">
                            <input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Send Verification Link">
                        </p>
                    </form>
                    <p id="backtoblog">
                        <a href="#" class="cancel-verification">&larr; Cancel Auto Login</a>
                    </p>
                </div>
            </div>
        `);

        // Add WordPress login styles
        if ($('#secure-login-styles').length === 0) {
            var styles = `
                <style id="secure-login-styles">
                    #secure-login-modal #login {
                        font-family: -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen-Sans,Ubuntu,Cantarell,"Helvetica Neue",sans-serif;
                    }
                    #secure-login-modal h1 {
                        text-align: center;
                        margin-bottom: 24px;
                    }
                    #secure-login-modal h1 a {
                        text-decoration: none;
                    }
                    #secure-login-modal .message {
                        background: #f0f0f1;
                        border-left: 4px solid #72aee6;
                        padding: 12px;
                        margin: -24px -24px 24px;
                    }
                    #secure-login-modal label {
                        font-size: 14px;
                        color: #3c434a;
                        display: block;
                        margin-bottom: 4px;
                    }
                    #secure-login-modal .input {
                        font-size: 24px;
                        width: 100%;
                        padding: 3px;
                        margin: 2px 6px 16px 0;
                        border: 1px solid #8c8f94;
                        background: #fff;
                        box-shadow: 0 0 0 transparent;
                        border-radius: 4px;
                        line-height: 1.33333333;
                        min-height: 40px;
                    }
                    #secure-login-modal .button {
                        display: inline-block;
                        font-size: 13px;
                        line-height: 2.15384615;
                        min-height: 30px;
                        margin: 0;
                        padding: 0 10px;
                        cursor: pointer;
                        border-width: 1px;
                        border-style: solid;
                        border-radius: 3px;
                        white-space: nowrap;
                        box-sizing: border-box;
                        background: #2271b1;
                        border-color: #2271b1;
                        color: #fff;
                        text-decoration: none;
                        width: 100%;
                        text-align: center;
                    }
                    #secure-login-modal #backtoblog {
                        margin: 24px 0 0;
                        text-align: center;
                    }
                    #secure-login-modal #backtoblog a {
                        color: #50575e;
                        text-decoration: none;
                    }
                </style>
            `;
            $('head').append(styles);
        }

        // Handle form submission
        modal.find('form').on('submit', function(e) {
            e.preventDefault();
            var email = $('#user-email').val();
            
            $.ajax({
                url: secureAutoLogin.ajax_url,
                type: 'POST',
                data: {
                    action: 'secure_auto_login_verify',
                    nonce: secureAutoLogin.nonce,
                    email: email
                },
                success: function(response) {
                    if (response.success) {
                        modal.find('form').replaceWith(`
                            <div class="message" style="margin: 0 0 16px;">
                                ${response.data.message}
                            </div>
                        `);
                    } else {
                        modal.find('.message').html(response.data.message)
                            .css('border-left-color', '#d63638');
                    }
                }
            });
        });

        // Handle cancel button
        modal.find('.cancel-verification').on('click', function(e) {
            e.preventDefault();
            modal.remove();
        });

        // Add to page
        $('body').append(modal);
    }

    // Try auto-login immediately
    attemptLogin();
}); 