use anyhow::Result;
use resend_rs::{types::CreateEmailBaseOptions, Resend};
use std::collections::HashMap;
use std::fs;

pub struct EmailService {
    client: Resend,
}

impl EmailService {
    pub fn new() -> Result<Self> {
        let api_key = std::env::var("RESEND_API_KEY")
            .map_err(|_| anyhow::anyhow!("RESEND_API_KEY environment variable not set"))?;
        
        let client = Resend::new(&api_key);
        
        Ok(Self { client })
    }

    pub async fn send_signup_confirmation(
        &self,
        to_email: &str,
        user_name: &str,
        confirmation_token: &str,
        base_url: &str,
    ) -> Result<()> {
        let confirmation_url = format!("{}/auth/confirm-email?token={}", base_url, confirmation_token);
        
        let mut variables = HashMap::new();
        variables.insert("user_name".to_string(), user_name.to_string());
        variables.insert("confirmation_url".to_string(), confirmation_url);

        let html_content = self.load_template("confirmation.html", &variables)?;

        let email_domain = std::env::var("EMAIL_DOMAIN").unwrap_or_else(|_| "delivered@resend.dev".to_string());
        let email_options = CreateEmailBaseOptions {
            from: format!("noreply@{}", email_domain),
            to: vec![to_email.to_string()],
            subject: "Please confirm your email address".to_string(),
            html: Some(html_content),
            text: None,
            cc: None,
            bcc: None,
            reply_to: None,
            attachments: None,
            tags: None,
            headers: None,
        };

        self.client.emails.send(email_options).await
            .map_err(|e| anyhow::anyhow!("Failed to send confirmation email: {}", e))?;

        Ok(())
    }

    pub async fn send_password_reset(
        &self,
        to_email: &str,
        user_name: &str,
        reset_token: &str,
        base_url: &str,
    ) -> Result<()> {
        let reset_url = format!("{}/auth/reset-password?token={}", base_url, reset_token);
        
        let mut variables = HashMap::new();
        variables.insert("user_name".to_string(), user_name.to_string());
        variables.insert("reset_url".to_string(), reset_url);

        let html_content = self.load_template("password_reset.html", &variables)?;

        let email_domain = std::env::var("EMAIL_DOMAIN").unwrap_or_else(|_| "delivered@resend.dev".to_string());
        let email_options = CreateEmailBaseOptions {
            from: format!("noreply@{}", email_domain),
            to: vec![to_email.to_string()],
            subject: "Reset your password".to_string(),
            html: Some(html_content),
            text: None,
            cc: None,
            bcc: None,
            reply_to: None,
            attachments: None,
            tags: None,
            headers: None,
        };

        self.client.emails.send(email_options).await
            .map_err(|e| anyhow::anyhow!("Failed to send password reset email: {}", e))?;

        Ok(())
    }

    fn load_template(&self, template_name: &str, variables: &HashMap<String, String>) -> Result<String> {
        let template_path = format!("src/emails/templates/{}", template_name);
        let mut content = fs::read_to_string(&template_path)
            .map_err(|e| anyhow::anyhow!("Failed to read template {}: {}", template_name, e))?;
        
        for (key, value) in variables {
            let placeholder = format!("{{{{{}}}}}", key);
            content = content.replace(&placeholder, value);
        }
        
        Ok(content)
    }
}