"""Microsoft Teams webhook integration for sending Adaptive Cards"""
import json
import logging
from typing import Optional, Dict, Any
import requests
from .config import Config

logger = logging.getLogger(__name__)


def build_adaptive_card_from_report(report_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build an Adaptive Card from report data.
    
    Args:
        report_data: Dictionary containing report information with keys:
            - id: Run ID
            - configuration_name: Name of the configuration
            - status: Status (success, error, running)
            - message: Status message
            - started_at: Start timestamp
            - completed_at: Completion timestamp (optional)
            - duration_seconds: Duration in seconds (optional)
            - errors: List of errors (optional)
            - execution_details: Execution details dictionary (optional)
    
    Returns:
        Adaptive Card JSON structure
    """
    run_id = report_data.get('id', 'N/A')
    config_name = report_data.get('configuration_name', 'Manual Run')
    status = report_data.get('status', 'unknown')
    message = report_data.get('message', '')
    started_at = report_data.get('started_at', 'N/A')
    completed_at = report_data.get('completed_at')
    duration_seconds = report_data.get('duration_seconds')
    errors = report_data.get('errors', [])
    execution_details = report_data.get('execution_details', {})
    
    # Debug logging to see what data we have
    logger.info(f"Building Adaptive Card for run {run_id} - execution_details keys: {list(execution_details.keys()) if execution_details else 'None'}")
    if execution_details:
        logger.info(f"  - templates_count: {execution_details.get('templates_count', 'N/A')}")
        logger.info(f"  - templates: {len(execution_details.get('templates', []))} items")
        logger.info(f"  - hosts_count: {execution_details.get('hosts_count', 'N/A')}")
        logger.info(f"  - ssh_profile: {bool(execution_details.get('ssh_profile'))}")
        logger.info(f"  - install_select: {execution_details.get('install_select', 'N/A')}")
        logger.info(f"  - installed: {execution_details.get('installed', 'N/A')}")
        logger.info(f"  - installations_count: {execution_details.get('installations_count', 'N/A')}")
    
    # Determine status color and icon
    if status == 'success':
        status_color = "Good"
        status_icon = "✅"
        status_text = "Success"
    elif status == 'error':
        status_color = "Attention"
        status_icon = "❌"
        status_text = "Error"
    else:
        status_color = "Warning"
        status_icon = "⏳"
        status_text = "Running"
    
    # Format duration
    duration_text = "N/A"
    if duration_seconds is not None:
        if duration_seconds < 60:
            duration_text = f"{int(duration_seconds)}s"
        elif duration_seconds < 3600:
            duration_text = f"{int(duration_seconds // 60)}m {int(duration_seconds % 60)}s"
        else:
            hours = int(duration_seconds // 3600)
            minutes = int((duration_seconds % 3600) // 60)
            duration_text = f"{hours}h {minutes}m"
    
    # Build card body
    card_body = [
        {
            "type": "TextBlock",
            "text": f"{status_icon} **{config_name}**",
            "size": "Large",
            "weight": "Bolder",
            "wrap": True
        },
        {
            "type": "FactSet",
            "facts": [
                {
                    "title": "Status:",
                    "value": status_text
                },
                {
                    "title": "Run ID:",
                    "value": str(run_id)
                },
                {
                    "title": "Started:",
                    "value": started_at
                }
            ]
        }
    ]
    
    # Add completion time if available
    if completed_at:
        card_body[1]["facts"].append({
            "title": "Completed:",
            "value": completed_at
        })
    
    # Add duration
    card_body[1]["facts"].append({
        "title": "Duration:",
        "value": duration_text
    })
    
    # Add message if available
    if message:
        card_body.append({
            "type": "TextBlock",
            "text": f"**Message:** {message}",
            "wrap": True,
            "spacing": "Medium"
        })
    
    # Add number of hosts
    hosts_count = execution_details.get('hosts_count', 0)
    hosts = execution_details.get('hosts', [])
    if hosts_count > 0:
        card_body.append({
            "type": "TextBlock",
            "text": "**Hosts**",
            "weight": "Bolder",
            "spacing": "Medium"
        })
        card_body.append({
            "type": "FactSet",
            "facts": [
                {
                    "title": "Total Hosts:",
                    "value": str(hosts_count)
                }
            ]
        })
    
    # Add templates created
    templates = execution_details.get('templates', [])
    templates_count = execution_details.get('templates_count', 0)
    if templates_count > 0:
        card_body.append({
            "type": "TextBlock",
            "text": "**Templates Created**",
            "weight": "Bolder",
            "spacing": "Medium"
        })
        
        # Show template list (limit to first 5 to avoid card being too large)
        templates_to_show = templates[:5]
        
        # Add each template as a separate TextBlock for better formatting
        for t in templates_to_show:
            template_name = t.get('template_name', 'N/A')
            version = t.get('version', 'N/A')
            repo_name = t.get('repo_name', 'N/A')
            card_body.append({
                "type": "TextBlock",
                "text": f"• {template_name} v{version} ({repo_name})",
                "wrap": True,
                "spacing": "Small"
            })
        
        if templates_count > 5:
            card_body.append({
                "type": "TextBlock",
                "text": f"*... and {templates_count - 5} more template(s)*",
                "wrap": True,
                "spacing": "Small",
                "isSubtle": True
            })
    
    # Add SSH Command Profile information
    ssh_profile = execution_details.get('ssh_profile')
    if ssh_profile:
        profile_name = ssh_profile.get('profile_name', 'N/A')
        profile_id = ssh_profile.get('profile_id')
        commands = ssh_profile.get('commands', [])
        commands_count = len(commands) if isinstance(commands, list) else 0
        wait_time = ssh_profile.get('wait_time_seconds', 0)
        ssh_hosts = ssh_profile.get('hosts', [])
        
        successful_ssh = 0
        failed_ssh = 0
        if ssh_hosts:
            successful_ssh = len([h for h in ssh_hosts if h.get('success', False)])
            failed_ssh = len([h for h in ssh_hosts if not h.get('success', True)])
        
        card_body.append({
            "type": "TextBlock",
            "text": "**SSH Command Profile**",
            "weight": "Bolder",
            "spacing": "Medium"
        })
        
        ssh_facts = [
            {
                "title": "Profile:",
                "value": f"{profile_name}" + (f" (ID: {profile_id})" if profile_id else "")
            },
            {
                "title": "Commands:",
                "value": f"{commands_count} command(s)"
            }
        ]
        
        if wait_time and wait_time > 0:
            ssh_facts.append({
                "title": "Wait Time:",
                "value": f"{wait_time}s"
            })
        
        if ssh_hosts:
            ssh_facts.append({
                "title": "Hosts Executed:",
                "value": f"{successful_ssh} successful, {failed_ssh} failed"
            })
        
        card_body.append({
            "type": "FactSet",
            "facts": ssh_facts
        })
    
    # Add Workspace Installation information
    install_select = execution_details.get('install_select', False)
    install_executed = execution_details.get('install_executed', False)
    installed = execution_details.get('installed')
    installations_count = execution_details.get('installations_count', 0)
    
    if install_select or install_executed:
        card_body.append({
            "type": "TextBlock",
            "text": "**Workspace Installation**",
            "weight": "Bolder",
            "spacing": "Medium"
        })
        
        install_facts = [
            {
                "title": "Enabled:",
                "value": "Yes" if install_select else "No"
            }
        ]
        
        # Always show template if installation is enabled, even if not executed yet
        if install_select and installed:
            template_name = installed.get('template_name', 'N/A')
            version = installed.get('version', 'N/A')
            repo_name = installed.get('repo_name', 'N/A')
            install_facts.append({
                "title": "Template:",
                "value": f"{template_name} v{version}"
            })
            install_facts.append({
                "title": "Repository:",
                "value": repo_name
            })
        elif install_select:
            # Installation was enabled but template info might not be in 'installed' field
            # Try to get it from installations array if available
            installations = execution_details.get('installations', [])
            if installations and len(installations) > 0:
                first_install = installations[0]
                template_name = first_install.get('template_name', 'N/A')
                version = first_install.get('version', 'N/A')
                repo_name = first_install.get('repo_name', 'N/A')
                if template_name != 'N/A':
                    install_facts.append({
                        "title": "Template:",
                        "value": f"{template_name} v{version}"
                    })
                    install_facts.append({
                        "title": "Repository:",
                        "value": repo_name
                    })
        
        card_body.append({
            "type": "FactSet",
            "facts": install_facts
        })
    
    # Add host summary (successful/failed breakdown) if available
    host_summary = execution_details.get('host_summary', {})
    
    # Calculate host summary if not directly available
    if not host_summary and hosts_count > 0:
        # Try to infer from fabric_creations or other execution details
        fabric_creations = execution_details.get('fabric_creations', [])
        if fabric_creations:
            # Count unique hosts, not fabric creations (multiple templates can be created on same host)
            unique_hosts = set()
            successful_unique_hosts = set()
            failed_unique_hosts = set()
            
            for fc in fabric_creations:
                host = fc.get('host')
                if host:
                    unique_hosts.add(host)
                    if fc.get('success', False):
                        successful_unique_hosts.add(host)
                    else:
                        failed_unique_hosts.add(host)
            
            # If we have host information, use it; otherwise fall back to hosts_count
            if unique_hosts:
                successful_hosts = len(successful_unique_hosts)
                failed_hosts = len(failed_unique_hosts)
                total_hosts = len(unique_hosts)
            else:
                # Fallback: use hosts_count from execution_details
                successful_hosts = hosts_count if not errors else 0
                failed_hosts = 0 if not errors else hosts_count
                total_hosts = hosts_count
            
            host_summary = {
                'total': total_hosts,
                'successful': successful_hosts,
                'failed': failed_hosts
            }
        else:
            # Fallback: use hosts_count as total, assume all successful if no errors
            host_summary = {
                'total': hosts_count,
                'successful': hosts_count if not errors else 0,
                'failed': 0 if not errors else hosts_count
            }
    
    if host_summary:
        total_hosts = host_summary.get('total', 0)
        successful_hosts = host_summary.get('successful', 0)
        failed_hosts = host_summary.get('failed', 0)
        
        # Only show execution summary if we have meaningful data and it matches hosts_count
        # This prevents showing incorrect counts when multiple templates are created on same host
        if total_hosts > 0 and total_hosts == hosts_count and (successful_hosts > 0 or failed_hosts > 0):
            card_body.append({
                "type": "TextBlock",
                "text": "**Execution Summary**",
                "weight": "Bolder",
                "spacing": "Medium"
            })
            card_body.append({
                "type": "FactSet",
                "facts": [
                    {
                        "title": "Successful Hosts:",
                        "value": str(successful_hosts)
                    },
                    {
                        "title": "Failed Hosts:",
                        "value": str(failed_hosts)
                    }
                ]
            })
    
    # Add errors if any
    if errors and len(errors) > 0:
        card_body.append({
            "type": "TextBlock",
            "text": "**Errors:**",
            "weight": "Bolder",
            "color": "Attention",
            "spacing": "Medium"
        })
        
        # Show first 5 errors to avoid card being too large
        errors_to_show = errors[:5]
        error_text = "\n".join([f"• {error}" for error in errors_to_show])
        if len(errors) > 5:
            error_text += f"\n\n*... and {len(errors) - 5} more errors*"
        
        card_body.append({
            "type": "TextBlock",
            "text": error_text,
            "wrap": True,
            "color": "Attention"
        })
    
    # Build the Adaptive Card
    adaptive_card = {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.4",
        "body": card_body
    }
    
    return adaptive_card


def send_teams_notification(report_data: Dict[str, Any]) -> bool:
    """
    Send an Adaptive Card notification to Microsoft Teams webhook.
    
    This function is optional - if TEAMS_WEBHOOK_URL is not configured,
    it will silently skip sending notifications.
    
    Args:
        report_data: Report data dictionary
    
    Returns:
        True if notification was sent successfully, False otherwise
    """
    webhook_url = Config.TEAMS_WEBHOOK_URL
    
    # If webhook URL is not configured, silently skip (Teams integration is optional)
    if not webhook_url or not webhook_url.strip():
        return False
    
    try:
        # Build Adaptive Card
        adaptive_card = build_adaptive_card_from_report(report_data)
        
        # Teams webhook expects the card in a specific format
        payload = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": adaptive_card
                }
            ]
        }
        
        # Send to Teams webhook
        response = requests.post(
            webhook_url,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        
        # Teams webhooks return 200 (OK) or 202 (Accepted) for success
        if response.status_code in (200, 202):
            logger.info(f"Successfully sent Teams notification for run ID {report_data.get('id')}")
            return True
        else:
            logger.warning(
                f"Failed to send Teams notification: HTTP {response.status_code} - {response.text}"
            )
            return False
            
    except requests.exceptions.RequestException as e:
        logger.error(f"Error sending Teams notification: {e}", exc_info=True)
        return False
    except Exception as e:
        logger.error(f"Unexpected error sending Teams notification: {e}", exc_info=True)
        return False

