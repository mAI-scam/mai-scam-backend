"""
Report Email Utilities for MAI Scam Detection System

This module provides utilities for sending scam reports to authorities via email.
It handles SMTP configuration, email templating, and report formatting for different scam types.
"""

import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from typing import Dict, Any, Optional
from datetime import datetime
import uuid
import logging

from setting import Setting

config = Setting()
logger = logging.getLogger(__name__)

class EmailReportSender:
    """
    Handles sending scam reports to authorities via email
    """
    
    def __init__(self):
        self.smtp_host = config.get('SMTP_HOST')
        self.smtp_port = int(config.get('SMTP_PORT', 587))
        self.smtp_username = config.get('SMTP_USERNAME')
        self.smtp_password = config.get('SMTP_PASSWORD')
        smtp_use_tls = config.get('SMTP_USE_TLS', True)
        self.smtp_use_tls = smtp_use_tls if isinstance(smtp_use_tls, bool) else str(smtp_use_tls).lower() == 'true'
        self.sender_name = config.get('SMTP_SENDER_NAME', 'MAI Scam Detection')
        self.report_email = config.get('REPORT_EMAIL')
        
        # Validate required SMTP configuration
        if not all([self.smtp_host, self.smtp_username, self.smtp_password, self.report_email]):
            logger.error("Missing required SMTP configuration values")
            logger.error(f"SMTP_HOST: {self.smtp_host}")
            logger.error(f"SMTP_USERNAME: {self.smtp_username}")
            logger.error(f"SMTP_PASSWORD: {'***' if self.smtp_password else None}")
            logger.error(f"REPORT_EMAIL: {self.report_email}")

    async def send_scam_report(self, scam_type: str, report_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send a scam report email to authorities
        
        Args:
            scam_type: Type of scam (email, website, socialmedia)
            report_data: Dictionary containing all scam analysis data
            
        Returns:
            Dictionary with success status and report ID
        """
        try:
            # Generate unique report ID
            report_id = f"RPT-{datetime.now().strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}"
            
            # Create email content
            subject = self._generate_subject(scam_type, report_data)
            body = self._generate_email_body(scam_type, report_data, report_id)
            
            # Send email
            success = await self._send_email(subject, body, report_id)
            
            if success:
                logger.info(f"Scam report sent successfully: {report_id}")
                return {
                    "success": True,
                    "report_id": report_id,
                    "message": "Report sent to authorities successfully"
                }
            else:
                logger.error(f"Failed to send scam report: {report_id}")
                return {
                    "success": False,
                    "report_id": report_id,
                    "message": "Failed to send report"
                }
                
        except Exception as e:
            logger.error(f"Error sending scam report: {str(e)}")
            return {
                "success": False,
                "report_id": None,
                "message": f"Error: {str(e)}"
            }

    def _generate_subject(self, scam_type: str, report_data: Dict[str, Any]) -> str:
        """Generate email subject line"""
        risk_level = report_data.get('risk_level', 'UNKNOWN').upper()
        scam_type_display = {
            'email': 'Email Scam',
            'website': 'Website Scam', 
            'socialmedia': 'Social Media Scam'
        }.get(scam_type, 'Scam')
        
        return f"[SCAM REPORT] {scam_type_display} - Risk Level: {risk_level}"

    def _generate_email_body(self, scam_type: str, report_data: Dict[str, Any], report_id: str) -> str:
        """Generate formatted email body based on scam type"""
        
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
        
        if scam_type == 'email':
            return self._format_email_scam_report(report_data, report_id, timestamp)
        elif scam_type == 'website':
            return self._format_website_scam_report(report_data, report_id, timestamp)
        elif scam_type == 'socialmedia':
            return self._format_socialmedia_scam_report(report_data, report_id, timestamp)
        else:
            return self._format_generic_scam_report(report_data, report_id, timestamp)

    def _format_email_scam_report(self, data: Dict[str, Any], report_id: str, timestamp: str) -> str:
        """Format email scam report"""
        return f"""Dear Authorities,

EXECUTIVE SUMMARY:
A {data.get('risk_level', 'UNKNOWN').upper()}-risk email scam has been detected by our AI system. This email exhibits characteristics typical of phishing, fraud, or other malicious activities targeting users.

═══════════════════════════════════════════════════════════════

📧 EMAIL SCAM DETAILS:
From: {data.get('from_email', 'Unknown')}
Reply-To: {data.get('reply_to_email', 'Not specified')}
Subject: {data.get('subject', 'No subject')}

Content:
{data.get('content', 'No content available')}

═══════════════════════════════════════════════════════════════

🤖 AI ANALYSIS RESULTS:
Risk Level: {data.get('risk_level', 'UNKNOWN').upper()}

Analysis:
{data.get('analysis', 'No analysis available')}

Recommended Action:
{data.get('recommended_action', 'No recommendations available')}

═══════════════════════════════════════════════════════════════

⚡ RECOMMENDED AUTHORITY ACTIONS:
1. Investigate the sender email domain and infrastructure
2. Check for similar campaigns targeting other users
3. Consider blocking the sender domain if confirmed malicious
4. Add to threat intelligence databases for future detection
5. Issue public warnings if this is part of a larger campaign

═══════════════════════════════════════════════════════════════

📋 TECHNICAL METADATA:
Report ID: {report_id}
Detection Time: {timestamp}
Detected Language: {data.get('detected_language', 'Unknown')}
Content Hash: {data.get('content_hash', 'Not available')}

Thank you for your attention to this matter. This report was generated automatically by the MAI Scam Detection System.

Best regards,
MAI Scam Detection Team
"""

    def _format_website_scam_report(self, data: Dict[str, Any], report_id: str, timestamp: str) -> str:
        """Format website scam report"""
        return f"""Dear Authorities,

EXECUTIVE SUMMARY:
A {data.get('risk_level', 'UNKNOWN').upper()}-risk website scam has been detected by our AI system. This website contains content or characteristics that pose risks to users through fraudulent schemes, phishing attempts, or other malicious activities.

═══════════════════════════════════════════════════════════════

🌐 WEBSITE SCAM DETAILS:
URL: {data.get('url', 'Unknown URL')}
Title: {data.get('title', 'No title available')}

Content:
{data.get('content', 'No content available')}

═══════════════════════════════════════════════════════════════

🤖 AI ANALYSIS RESULTS:
Risk Level: {data.get('risk_level', 'UNKNOWN').upper()}

Analysis:
{data.get('analysis', 'No analysis available')}

Recommended Action:
{data.get('recommended_action', 'No recommendations available')}

═══════════════════════════════════════════════════════════════

⚡ RECOMMENDED AUTHORITY ACTIONS:
1. Investigate the website domain and hosting infrastructure
2. Check domain registration details and ownership
3. Consider requesting takedown from hosting providers
4. Add to browser security blacklists if confirmed malicious
5. Monitor for similar scam websites using the same patterns
6. Issue public warnings about this specific website

═══════════════════════════════════════════════════════════════

📋 TECHNICAL METADATA:
Report ID: {report_id}
Detection Time: {timestamp}
Detected Language: {data.get('detected_language', 'Unknown')}
Content Hash: {data.get('content_hash', 'Not available')}

Thank you for your attention to this matter. This report was generated automatically by the MAI Scam Detection System.

Best regards,
MAI Scam Detection Team
"""

    def _format_socialmedia_scam_report(self, data: Dict[str, Any], report_id: str, timestamp: str) -> str:
        """Format social media scam report"""
        platform = data.get('platform', 'Unknown Platform').title()
        
        return f"""Dear Authorities,

EXECUTIVE SUMMARY:
A {data.get('risk_level', 'UNKNOWN').upper()}-risk social media scam has been detected on {platform}. This post exhibits characteristics of fraudulent schemes, fake promotions, or other malicious activities targeting social media users.

═══════════════════════════════════════════════════════════════

📱 SOCIAL MEDIA SCAM DETAILS:
Platform: {platform}
Author: {data.get('author_username', 'Unknown')}
Post URL: {data.get('post_url', 'Not available')}
Followers Count: {data.get('author_followers_count', 'Unknown')}

Content:
{data.get('content', 'No content available')}

═══════════════════════════════════════════════════════════════

🤖 AI ANALYSIS RESULTS:
Risk Level: {data.get('risk_level', 'UNKNOWN').upper()}

Analysis:
{data.get('analysis', 'No analysis available')}

Text Analysis:
{data.get('text_analysis', 'Not available')}

Image Analysis:
{data.get('image_analysis', 'No image analyzed')}

Recommended Action:
{data.get('recommended_action', 'No recommendations available')}

═══════════════════════════════════════════════════════════════

⚡ RECOMMENDED AUTHORITY ACTIONS:
1. Report the account to {platform} for policy violations
2. Request immediate takedown of the fraudulent post
3. Investigate account creation patterns and linked accounts
4. Monitor for similar scam posts from the same network
5. Issue public warnings about this type of {platform} scam
6. Coordinate with {platform} security team for broader investigation

═══════════════════════════════════════════════════════════════

📋 TECHNICAL METADATA:
Report ID: {report_id}
Detection Time: {timestamp}
Platform: {platform}
Multimodal Analysis: {data.get('multimodal', False)}
Content Hash: {data.get('content_hash', 'Not available')}

Thank you for your attention to this matter. This report was generated automatically by the MAI Scam Detection System.

Best regards,
MAI Scam Detection Team
"""

    def _format_generic_scam_report(self, data: Dict[str, Any], report_id: str, timestamp: str) -> str:
        """Format generic scam report for unknown types"""
        return f"""Dear Authorities,

EXECUTIVE SUMMARY:
A {data.get('risk_level', 'UNKNOWN').upper()}-risk scam has been detected by our AI system.

═══════════════════════════════════════════════════════════════

🚨 SCAM DETAILS:
{data.get('content', 'No content available')}

═══════════════════════════════════════════════════════════════

🤖 AI ANALYSIS RESULTS:
Risk Level: {data.get('risk_level', 'UNKNOWN').upper()}

Analysis:
{data.get('analysis', 'No analysis available')}

Recommended Action:
{data.get('recommended_action', 'No recommendations available')}

═══════════════════════════════════════════════════════════════

📋 TECHNICAL METADATA:
Report ID: {report_id}
Detection Time: {timestamp}

Thank you for your attention to this matter. This report was generated automatically by the MAI Scam Detection System.

Best regards,
MAI Scam Detection Team
"""

    async def _send_email(self, subject: str, body: str, report_id: str) -> bool:
        """Send email using SMTP"""
        try:
            # Validate configuration before attempting to send
            if not all([self.smtp_host, self.smtp_username, self.smtp_password, self.report_email]):
                logger.error(f"SMTP configuration incomplete for report {report_id}")
                return False
            
            # Create message
            message = MIMEMultipart()
            message["From"] = f"{self.sender_name} <{self.smtp_username}>"
            message["To"] = self.report_email
            message["Subject"] = subject
            
            # Add body to email
            message.attach(MIMEText(body, "plain"))
            
            # Create SSL context
            context = ssl.create_default_context()
            
            # Create SMTP session
            logger.info(f"Connecting to SMTP server {self.smtp_host}:{self.smtp_port}")
            server = smtplib.SMTP(self.smtp_host, self.smtp_port)
            
            if self.smtp_use_tls:
                logger.info("Starting TLS connection")
                server.starttls(context=context)  # Enable TLS security with context
                
            # Login with sender's email and password
            logger.info("Authenticating with SMTP server")
            server.login(self.smtp_username, self.smtp_password)
            
            # Send email
            text = message.as_string()
            logger.info(f"Sending email to {self.report_email}")
            server.sendmail(self.smtp_username, self.report_email, text)
            server.quit()
            
            logger.info(f"Email sent successfully for report: {report_id}")
            return True
            
        except smtplib.SMTPAuthenticationError as e:
            logger.error(f"SMTP Authentication failed for report {report_id}: {str(e)}")
            return False
        except smtplib.SMTPConnectError as e:
            logger.error(f"SMTP Connection failed for report {report_id}: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"Failed to send email for report {report_id}: {str(e)}")
            return False


# Initialize global email sender instance
email_sender = EmailReportSender()

async def send_email_report(scam_type: str, report_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convenience function to send scam report email
    
    Args:
        scam_type: Type of scam (email, website, socialmedia)
        report_data: Dictionary containing scam analysis data
        
    Returns:
        Dictionary with success status and report ID
    """
    return await email_sender.send_scam_report(scam_type, report_data)