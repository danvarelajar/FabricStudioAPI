import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import time
import sys
import itertools
import logging
from .rate_limiter import wait_for_rate_limit, record_api_request

logger = logging.getLogger(__name__)


def _make_rate_limited_request(fabric_host, request_func, max_retries=3, retry_delay=1.0):
    """
    Make an API request with retry logic for rate limit errors and timeouts.
    
    NOTE: Client-side rate limiting is disabled. This function only handles
    retries when the API returns 429 errors or when requests timeout.
    
    Args:
        fabric_host: The Fabric host address
        request_func: A function that makes the request and returns the response
        max_retries: Maximum number of retries for rate limit errors and timeouts
        retry_delay: Initial delay between retries (will be doubled on each retry)
        
    Returns:
        The response object
        
    Raises:
        RuntimeError: If the request fails after all retries
    """
    # Rate limiting disabled - make request immediately
    
    for attempt in range(max_retries + 1):
        try:
            response = request_func()
            
            # Check for rate limit error from API
            if response.status_code == 429:
                # Parse retry-after header if available
                retry_after = response.headers.get('Retry-After')
                if retry_after:
                    try:
                        wait_time = float(retry_after)
                    except ValueError:
                        wait_time = retry_delay * (2 ** attempt)
                else:
                    wait_time = retry_delay * (2 ** attempt)
                
                if attempt < max_retries:
                    logger.warning(
                        "Rate limit exceeded for %s (attempt %d/%d). Waiting %.2f seconds",
                        fabric_host, attempt + 1, max_retries + 1, wait_time
                    )
                    time.sleep(wait_time)
                    continue
                else:
                    error_msg = f"Rate limit exceeded by API server."
                    logger.error("Rate limit exceeded for %s after %d attempts", fabric_host, max_retries + 1)
                    raise RuntimeError(error_msg)
            
            return response
            
        except requests.Timeout as exc:
            # Handle timeout errors specifically - retry with longer delay
            if attempt < max_retries:
                wait_time = retry_delay * (2 ** attempt) * 2  # Longer delay for timeouts
                logger.warning(
                    "Request timeout for %s (attempt %d/%d). Retrying in %.2f seconds",
                    fabric_host, attempt + 1, max_retries + 1, wait_time
                )
                time.sleep(wait_time)
                continue
            else:
                logger.error("Request timeout for %s after %d attempts", fabric_host, max_retries + 1)
                raise RuntimeError(f"Request timeout after {max_retries + 1} attempts: {exc}")
        except requests.RequestException as exc:
            if attempt < max_retries:
                wait_time = retry_delay * (2 ** attempt)
                logger.warning(
                    "Request failed for %s (attempt %d/%d): %s. Retrying in %.2f seconds",
                    fabric_host, attempt + 1, max_retries + 1, exc, wait_time
                )
                time.sleep(wait_time)
                continue
            else:
                raise RuntimeError(f"Request failed after {max_retries + 1} attempts: {exc}")
    
    raise RuntimeError(f"Request failed after {max_retries + 1} attempts")

def check_tasks(fabric_host, access_token, display_progress=False):
    logger.info("Checking for running tasks on host %s", fabric_host)
    url = f"https://{fabric_host}/api/v1/task?running=true"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Cache-Control": "no-cache"
    }
    try:
        response = requests.get(url, headers=headers, verify=False, timeout=30)
    except requests.RequestException as exc:
        logger.error("Error querying tasks: %s", exc)
        return None
    if response.status_code != 200:
        logger.error("Error querying tasks: %s - %s", response.status_code, response.text)
        return None
    try:
        data = response.json()
    except ValueError:
        logger.error("Error parsing tasks response as JSON")
        return None
    start = time.time()
    logger.info("Task polling started")
    max_wait_time = 15 * 60  # 15 minutes in seconds
    waited = 0
    previous_count = data.get("page", {}).get("count", 0)
    last_progress_log = 0
    spinner = itertools.cycle(['|', '/', '-', '\\']) if display_progress else None
    while data.get("page", {}).get("count", 0) != 0 and waited < max_wait_time:
        time.sleep(2)
        waited += 2
        try:
            response = requests.get(url, headers=headers, verify=False, timeout=30)
        except requests.RequestException as exc:
            logger.error("Error polling tasks: %s", exc)
            break
        if response.status_code != 200:
            logger.error("Error polling tasks: %s - %s", response.status_code, response.text)
            break
        try:
            data = response.json()
        except ValueError:
            logger.error("Error parsing polling response as JSON")
            break
        current_count = data.get("page", {}).get("count", 0)
        # Reduce verbosity: only log start/finish at INFO level
        # Keep progress as DEBUG (optional visibility without cluttering INFO logs)
        if current_count != previous_count or (waited - last_progress_log) >= 10:
            logger.debug("Tasks running: %d, waited %ds", current_count, waited)
            previous_count = current_count
            last_progress_log = waited
        if display_progress:
            sys.stdout.write("\rWaiting for tasks... %d running %s Elapsed: %ds" % (
                current_count,
                next(spinner),
                waited,
            ))
            sys.stdout.flush()
    if waited >= max_wait_time and data.get("page", {}).get("count", 0) != 0:
        logger.error("Timed out waiting for tasks to finish after 15 minutes")
        if display_progress:
            sys.stdout.write("\n")
        end = time.time()
        difference = (end - start)/60
        logger.info("Task polling completed in %.2f minutes", difference)
        return (difference, False)  # Return (elapsed_time, success)
    if display_progress:
        sys.stdout.write("\n")
    end = time.time()
    difference = (end - start)/60
    logger.info("Task polling completed in %.2f minutes", difference)
    return (difference, True)  # Return (elapsed_time, success)


def get_running_task_count(fabric_host, access_token):
    """Return current count of running tasks without waiting.
    Returns (count, error_message) tuple. If successful, error_message is None.
    If failed, count is None and error_message contains the error details.
    """
    url = f"https://{fabric_host}/api/v1/task?running=true"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Cache-Control": "no-cache"
    }
    try:
        response = requests.get(url, headers=headers, verify=False, timeout=15)
    except requests.RequestException as exc:
        error_msg = f"Network error querying task status: {str(exc)}"
        logger.error("Error querying task status: %s", exc)
        return (None, error_msg)
    if response.status_code != 200:
        error_msg = f"Task status API returned {response.status_code}: {response.text[:200]}"
        logger.error("Task status error: %s - %s", response.status_code, response.text)
        return (None, error_msg)
    try:
        data = response.json()
    except ValueError:
        error_msg = "Task status response is not valid JSON"
        logger.error("Task status JSON parse error")
        return (None, error_msg)
    count = data.get("page", {}).get("count", 0)
    return (count, None)


def get_recent_task_errors(fabric_host, access_token, limit=50, since_timestamp=None, fabric_name=None):
    """
    Query recent completed/failed tasks and extract error information.
    Returns a list of error dictionaries with task details.
    
    Args:
        limit: Maximum number of tasks to check
        since_timestamp: Only include tasks created after this timestamp (ISO format string or datetime)
        fabric_name: If provided, only include tasks related to this fabric name
    """
    logger.info("Checking for recent task errors on host %s", fabric_host)
    # Query recent tasks (completed and failed)
    # Use status filter if available, otherwise query all recent tasks
    url = f"https://{fabric_host}/api/v1/task"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Cache-Control": "no-cache"
    }
    params = {
        "per_page": limit,
        "page": 1
    }
    
    try:
        response = requests.get(url, headers=headers, params=params, verify=False, timeout=30)
    except requests.RequestException as exc:
        logger.error("Error querying recent tasks: %s", exc)
        return []
    
    if response.status_code != 200:
        logger.error("Error querying recent tasks: %s - %s", response.status_code, response.text)
        return []
    
    try:
        data = response.json()
    except ValueError:
        logger.error("Error parsing recent tasks response as JSON")
        return []
    
    errors = []
    tasks = data.get("object", [])
    
    # Parse since_timestamp if provided
    since_datetime = None
    if since_timestamp:
        try:
            if isinstance(since_timestamp, str):
                from datetime import datetime
                # Try parsing ISO format
                since_datetime = datetime.fromisoformat(since_timestamp.replace('Z', '+00:00'))
            elif hasattr(since_timestamp, 'isoformat'):
                since_datetime = since_timestamp
        except Exception as e:
            logger.warning("Could not parse since_timestamp %s: %s", since_timestamp, e)
    
    def extract_error_from_task(task):
        """Extract error message from task, checking multiple possible locations."""
        error_msg = None
        
        # First check returncode in task object (most reliable indicator)
        # The task object might be nested under 'object' key or directly accessible
        task_obj = task.get("object", task)
        returncode = task_obj.get("returncode")
        if returncode is not None and returncode != 0:
            task_name = task_obj.get("name", task.get("name", "Unknown Task"))
            error_msg = f"Task '{task_name}' failed with returncode: {returncode}"
        
        # Check result field for nested error structures
        result = task.get("result")
        if result:
            # If result is a dict, check for error indicators
            if isinstance(result, dict):
                # Check for status='error' in result
                if result.get("status", "").lower() == "error":
                    # Extract error messages from nested errors dict
                    errors_dict = result.get("errors", {})
                    if errors_dict:
                        # Collect all error messages
                        error_parts = []
                        if "global" in errors_dict:
                            if isinstance(errors_dict["global"], list):
                                error_parts.extend(errors_dict["global"])
                            else:
                                error_parts.append(str(errors_dict["global"]))
                        # Collect other error keys
                        for key, value in errors_dict.items():
                            if key != "global":
                                if isinstance(value, list):
                                    error_parts.extend([f"{key}: {v}" for v in value])
                                else:
                                    error_parts.append(f"{key}: {value}")
                        if error_parts:
                            # Prepend returncode info if we have it
                            if error_msg:
                                error_msg = f"{error_msg}; " + "; ".join(error_parts)
                            else:
                                error_msg = "; ".join(error_parts)
                    # Fallback to result message or error field
                    if not error_msg:
                        error_msg = result.get("message", "") or result.get("error", "")
                    # Check rcode - if it's an error code, include it
                    rcode = result.get("rcode")
                    if rcode and str(rcode) != "0":
                        rcode_str = f" (rcode: {rcode})"
                        error_msg = error_msg + rcode_str if error_msg else f"Error rcode: {rcode}"
                # Check for errors dict directly in result (even if status is not 'error')
                elif "errors" in result and result.get("errors"):
                    errors_dict = result.get("errors", {})
                    if isinstance(errors_dict, dict):
                        error_parts = []
                        if "global" in errors_dict:
                            if isinstance(errors_dict["global"], list):
                                error_parts.extend(errors_dict["global"])
                            else:
                                error_parts.append(str(errors_dict["global"]))
                        for key, value in errors_dict.items():
                            if key != "global":
                                if isinstance(value, list):
                                    error_parts.extend([f"{key}: {v}" for v in value])
                                else:
                                    error_parts.append(f"{key}: {value}")
                        if error_parts:
                            # Prepend returncode info if we have it
                            if error_msg:
                                error_msg = f"{error_msg}; " + "; ".join(error_parts)
                            else:
                                error_msg = "; ".join(error_parts)
        
        # If no error found yet, check top-level error fields
        if not error_msg:
            error_msg = task.get("error", "") or task.get("message", "") or task.get("description", "")
        
        # Check rcode at task level (but returncode takes precedence)
        rcode = task.get("rcode")
        if rcode and str(rcode) != "0" and not error_msg:
            error_msg = f"Error rcode: {rcode}"
        
        return error_msg
    
    # Filter for failed or error tasks
    for task in tasks:
        # Handle both cases: task might be the object directly, or nested under 'object' key
        task_obj = task.get("object", task)
        task_id = task_obj.get("id") or task.get("id")
        task_name = task_obj.get("name") or task.get("name", "Unknown Task")
        
        # Filter by timestamp if provided
        if since_datetime:
            task_timestamp_str = task.get("created_at") or task.get("updated_at") or task_obj.get("created_date") or task_obj.get("returned_date")
            if task_timestamp_str:
                try:
                    from datetime import datetime
                    task_datetime = datetime.fromisoformat(task_timestamp_str.replace('Z', '+00:00'))
                    if task_datetime < since_datetime:
                        # Skip tasks created before the timestamp
                        continue
                except Exception:
                    # If we can't parse timestamp, include the task to be safe
                    pass
        
        # Check returncode FIRST - tasks with non-zero returncode are errors regardless of fabric_name
        # This ensures we catch errors like returncode 254 even if fabric_name filter would exclude them
        returncode = task_obj.get("returncode")
        has_non_zero_returncode = returncode is not None and returncode != 0
        
        # Filter by fabric name if provided (but skip this filter if task has non-zero returncode)
        # Tasks with non-zero returncode should always be included if they're within the timestamp window
        if fabric_name and not has_non_zero_returncode:
            # Check if task name contains fabric name or if fabric is mentioned in task
            # Fabric-related tasks often have the fabric name in the task name
            task_name_lower = task_name.lower()
            fabric_name_lower = fabric_name.lower()
            
            # Check fabric field if available
            task_fabric = task_obj.get("fabric") or task.get("fabric")
            fabric_match = False
            
            if task_fabric:
                if isinstance(task_fabric, dict):
                    fabric_obj_name = task_fabric.get("name")
                    if fabric_obj_name and fabric_obj_name.lower() == fabric_name_lower:
                        fabric_match = True
                elif isinstance(task_fabric, (int, str)):
                    # Fabric ID reference, we can't filter by this easily without additional API call
                    # Skip tasks with fabric ID references if we can't verify they match
                    # This is safer than including potentially wrong tasks
                    pass
            
            # Check if fabric name appears in task name (e.g., "Install Fabric 'FortiAppSec Cloud WAF'")
            if fabric_name_lower in task_name_lower:
                fabric_match = True
            
            # If fabric name is provided, only include tasks that explicitly match
            # Skip all tasks that don't match our fabric
            if not fabric_match:
                # If task mentions another fabric explicitly, definitely skip it
                if "fabric" in task_name_lower:
                    # Extract fabric names from task name (look for patterns like "Fabric 'XXX'")
                    import re
                    fabric_pattern = r"fabric\s+['\"]([^'\"]+)['\"]"
                    matches = re.findall(fabric_pattern, task_name_lower)
                    if matches:
                        # If any mentioned fabric doesn't match ours, skip this task
                        found_matching_fabric = False
                        for mentioned_fabric in matches:
                            if mentioned_fabric.lower() == fabric_name_lower:
                                found_matching_fabric = True
                                break
                        # If no matching fabric found, skip this task
                        if not found_matching_fabric:
                            continue
                    else:
                        # Task mentions "fabric" but doesn't explicitly name one, check if our fabric name appears anywhere
                        if fabric_name_lower not in task_name_lower:
                            # Task mentions fabric but not our fabric name, skip it
                            continue
                
                # For device/install tasks without fabric context, be very conservative
                # Only include if they were created very recently (within last 30 seconds)
                # This handles the case where device tasks are part of fabric creation
                if "device" in task_name_lower or ("install" in task_name_lower and "fabric" not in task_name_lower):
                    # Check if task was created very recently (within 30 seconds of operation start)
                    if since_datetime:
                        task_timestamp_str = task.get("created_at") or task.get("updated_at") or task_obj.get("created_date") or task_obj.get("returned_date")
                        if task_timestamp_str:
                            try:
                                from datetime import datetime, timedelta
                                task_datetime = datetime.fromisoformat(task_timestamp_str.replace('Z', '+00:00'))
                                time_diff = (task_datetime - since_datetime).total_seconds()
                                # Only include if created within 30 seconds of operation start
                                if time_diff > 30:
                                    continue
                            except Exception:
                                # If we can't parse timestamp, exclude to be safe
                                continue
                    else:
                        # No timestamp filter, exclude device tasks that don't match fabric
                        continue
                else:
                    # Not a fabric task and not a device task, skip if doesn't match
                    continue
        
        # Get status from top level or task object
        status = task.get("status", "").lower() or task_obj.get("status", "").lower()
        
        # Returncode was already checked above (before fabric_name filter)
        
        # Check for failed status, error messages, or non-zero returncode
        has_error = False
        if status in ["failed", "error", "exception"]:
            has_error = True
        elif returncode is not None and returncode != 0:
            # Task completed but with non-zero returncode indicates failure
            # Even if status is "done" or "completed", non-zero returncode means failure
            has_error = True
        elif status in ["completed", "done"]:
            # Check if there are errors in result field
            error_msg = extract_error_from_task(task)
            if error_msg:
                has_error = True
        
        if has_error:
            error_msg = extract_error_from_task(task)
            if not error_msg and returncode is not None and returncode != 0:
                # If no error message but returncode is non-zero, create one
                error_msg = f"Task '{task_name}' failed with returncode: {returncode}"
            
            if error_msg:
                errors.append({
                    "task_id": task_id,
                    "task_name": task_name,
                    "status": status,
                    "error": error_msg,
                    "timestamp": task.get("created_at") or task.get("updated_at") or task_obj.get("created_date") or task_obj.get("returned_date")
                })
                logger.warning("Found failed task: %s (id: %s) - returncode: %s - %s", task_name, task_id, returncode if returncode is not None else "N/A", error_msg)
    
    return errors


def query_hostname(fabric_host, access_token):
    logger.info("Querying hostname on host %s", fabric_host)
    url = f"https://{fabric_host}/api/v1/system/hostname"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Cache-Control": "no-cache"
    }
    try:
        response = requests.get(url, headers=headers, verify=False, timeout=30)
    except requests.RequestException as exc:
        logger.error("Error querying hostname: %s", exc)
        return None
    if response.status_code != 200:
        logger.error("Error querying hostname: %s - %s", response.status_code, response.text)
        return None
    try:
        data = response.json()
    except ValueError:
        logger.error("Error parsing hostname response as JSON")
        return None
    logger.info("Hostname response received")
    return data.get("object")


def change_hostname(fabric_host, access_token, hostname):
    logger.info("Changing hostname on host %s", fabric_host)
    url = f"https://{fabric_host}/api/v1/system/hostname"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Cache-Control": "no-cache"
    }
    data = {
        "hostname": hostname
    }
    try:
        response = requests.post(url, headers=headers, json=data, verify=False, timeout=30)
    except requests.RequestException as exc:
        logger.error("Error updating hostname: %s", exc)
        return None
    if response.status_code == 200:
        logger.info("Hostname updated successfully")
        return None
    else:
        logger.error("Error updating hostname: %s - %s", response.status_code, response.text)
        return None


def get_userId(fabric_host, access_token, username):
    #API fails
    logger.info("Looking up userId for username '%s' on host %s", username, fabric_host)
    url = f"https://{fabric_host}/api/v1/system/user"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Cache-Control": "no-cache"
    }
    params = {"select": f"username={username}"}
    try:
        response = _make_rate_limited_request(
            fabric_host,
            lambda: requests.get(url, headers=headers, params=params, verify=False, timeout=30)
        )
    except RuntimeError as exc:
        logger.error("Error finding user: %s", exc)
        return None
    except Exception as exc:
        logger.error("Error finding user: %s", exc)
        return None
    
    if response.status_code == 200:
        try:
            data = response.json()
        except ValueError:
            logger.error("Error parsing user lookup response as JSON")
            return None
        objects = data.get("object", [])
        if not objects:
            logger.info("User not found")
            return None
        found_username = objects[0].get("username")
        logger.info("User '%s' found with id %s", found_username, objects[0].get("id"))
        return objects[0].get("id")
    else:
        logger.error("Error finding user: %s - %s", response.status_code, response.text)
        return None


def change_password(fabric_host, access_token, user_id, password):
    logger.info("Changing password for user_id %s on host %s", user_id, fabric_host)
    # Correct endpoint path is /system/user/password/{id}
    url = f"https://{fabric_host}/api/v1/system/user/password/{user_id}"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Cache-Control": "no-cache",
        "Content-Type": "application/json"
    }
    data = {
        "current_password": "",
        "new_password": password,
        "encrypted": False
    }
    
    # Log request details
    logger.info("Password change request - URL: %s", url)
    logger.info("Password change request - Headers: %s", {k: v if k != "Authorization" else "Bearer ***" for k, v in headers.items()})
    logger.info("Password change request - Data: %s", {**data, "new_password": "***" if data.get("new_password") else ""})
    
    try:
        response = _make_rate_limited_request(
            fabric_host,
            lambda: requests.post(url, headers=headers, json=data, verify=False, timeout=30)
        )
        
        # Log response details
        logger.info("Password change response - Status: %s", response.status_code)
        logger.info("Password change response - Headers: %s", dict(response.headers))
        logger.info("Password change response - Body: %s", response.text)
        
    except RuntimeError as exc:
        logger.error("Error updating guest user password: %s", exc, exc_info=True)
        raise
    except requests.RequestException as exc:
        logger.error("Error updating guest user password: %s", exc, exc_info=True)
        raise RuntimeError(f"Failed to change password: {exc}")
    
    if response.status_code == 200:
        logger.info("Password updated for user_id %s", user_id)
        return True
    else:
        error_msg = f"Failed to change password: HTTP {response.status_code} - {response.text}"
        logger.error("Error updating guest user password: %s", error_msg)
        raise RuntimeError(error_msg)


def reset_fabric(fabric_host, access_token):
    """
    Reset fabric on host (asynchronous).
    Returns immediately after initiating the reset task.
    """
    logger.info("Initiating fabric reset on host %s", fabric_host)
    url = f"https://{fabric_host}/api/v1/runtime/fabric"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Cache-Control": "no-cache"
    }
    try:
        response = requests.delete(url, headers=headers, verify=False, timeout=30)
    except requests.RequestException as exc:
        logger.error("Error initiating reset Fabric: %s", exc)
        return False
    if response.status_code == 200:
        logger.info("Fabric reset task initiated successfully (async)")
        return True
    else:
        logger.error("Error initiating reset Fabric: %s - %s", response.status_code, response.text)
        return False


def batch_delete(fabric_host, access_token):
    """
    Delete all fabrics in batch on host (asynchronous).
    Returns immediately after initiating the delete task.
    """
    logger.info("Initiating batch delete of all fabrics on host %s", fabric_host)
    url = f"https://{fabric_host}/api/v1/model/fabric/batch?interactive=false"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Cache-Control": "no-cache"
    }
    try:
        response = requests.delete(url, headers=headers, verify=False, timeout=30)
    except requests.RequestException as exc:
        logger.error("Error initiating batch delete: %s", exc)
        return False
    if response.status_code == 200:
        logger.info("Batch delete task initiated successfully (async)")
        return True
    else:
        logger.error("Error initiating batch delete: %s - %s", response.status_code, response.text)
        return False


def refresh_repositories(fabric_host, access_token):
    """
    Refresh all remote repositories on host (asynchronous).
    Returns immediately after initiating the refresh task.
    
    Args:
        fabric_host: Fabric host address
        access_token: Access token for authentication
    
    Returns:
        True if API call was successful (task initiated), False otherwise
    """
    logger.info("Initiating refresh of all remote repositories on host %s", fabric_host)
    url = f"https://{fabric_host}/api/v1/system/repository/remote:refresh-all"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Cache-Control": "no-cache"
    }
    data = {
        "force": False
    }
    try:
        response = requests.post(url, headers=headers, json=data, verify=False, timeout=30)
    except requests.RequestException as exc:
        logger.error("Error initiating refresh all repositories: %s", exc)
        return False
    
    if response.status_code == 200:
        logger.info("Refresh all repositories task initiated successfully (async)")
        return True
    else:
        error_msg = f"{response.status_code} - {response.text}"
        logger.error("Error initiating refresh all repositories: %s", error_msg)
        return False


def get_repositoryId(fabric_host, access_token, repo_name):
    logger.info("Getting repository id for '%s' on host %s", repo_name, fabric_host)
    # Prefer listing and matching case-insensitively to avoid select quirks
    repos = list_repositories(fabric_host, access_token)
    if repos:
        wanted = (repo_name or "").strip().lower()
        for r in repos:
            name = (r.get('name') or "").strip().lower()
            code = (r.get('code') or "").strip().lower()
            if name == wanted or code == wanted:
                repo_id = r.get('id')
                logger.info("Repository '%s' resolved to id %s via list match", repo_name, repo_id)
                return repo_id
        logger.info("Repository '%s' not found in %d repos", repo_name, len(repos))
        return None
    # Fallback to direct query if listing failed returned empty
    url = f"https://{fabric_host}/api/v1/system/repository/remote"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Cache-Control": "no-cache"
    }
    params = {"select": f"name={repo_name}"}
    try:
        response = _make_rate_limited_request(
            fabric_host,
            lambda: requests.get(url, headers=headers, params=params, verify=False, timeout=30)
        )
    except (RuntimeError, requests.RequestException) as exc:
        logger.error("Error finding Repository Id: %s", exc)
        return None
    if response.status_code == 200:
        try:
            data = response.json()
        except ValueError:
            logger.error("Error parsing repository lookup response as JSON")
            return None
        objects = data.get('object', [])
        if not objects:
            logger.info("Repository '%s' not found", repo_name)
            return None
        repo_id = objects[0].get('id')
        logger.info("Repository '%s' resolved to id %s via direct query", repo_name, repo_id)
        return repo_id
    else:
        logger.error("Error finding Repository Id: %s - %s", response.status_code, response.text)
        return None


def list_repositories(fabric_host, access_token):
    """
    Return list of remote repositories (objects).
    
    Args:
        fabric_host: Fabric host address
        access_token: Access token for authentication
    
    Returns:
        List of repository objects
    """
    # Fetch from API
    url = f"https://{fabric_host}/api/v1/system/repository/remote"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Cache-Control": "no-cache"
    }
    try:
        response = _make_rate_limited_request(
            fabric_host,
            lambda: requests.get(url, headers=headers, verify=False, timeout=30)
        )
    except (RuntimeError, requests.RequestException) as exc:
        logger.error("Error listing repositories: %s", exc)
        return []
    
    if response.status_code != 200:
        logger.error("Error listing repositories: %s - %s", response.status_code, response.text)
        return []
    try:
        data = response.json()
    except ValueError:
        logger.error("Error parsing repositories response as JSON")
        return []
    
    repos = data.get('object', [])
    return repos


def get_template(fabric_host, access_token, template, repo_name, version):
    logger.info("Getting template '%s' (version=%s) in repo '%s' on host %s", template, version, repo_name, fabric_host)
    repo_id = get_repositoryId(fabric_host, access_token, repo_name)
    if not repo_id:
        logger.error("Repository '%s' not found when resolving template", repo_name)
        return None
    items = list_templates_for_repo(fabric_host, access_token, repo_id)
    t_norm = (template or "").strip().lower()
    v_norm = (version or "").strip()
    for item in items:
        name_norm = (item.get('name') or "").strip().lower()
        ver_val = (item.get('version') or "").strip()
        if name_norm == t_norm and ver_val == v_norm:
            logger.info("Template '%s' (version=%s) resolved to id %s", template, version, item.get('id'))
            return item.get('id')
    logger.info("Template '%s' (version=%s) not found", template, version)
    return None


def list_templates_for_repo(fabric_host, access_token, repo_id):
    base_url = f"https://{fabric_host}/api/v1/system/repository/template"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Cache-Control": "no-cache"
    }
    all_items = []
    page = 1
    per_page = 500
    while True:
        params = {
            "select": f"repository={repo_id}",
            "page": page,
            "per_page": per_page,
        }
        try:
            response = _make_rate_limited_request(
                fabric_host,
                lambda: requests.get(base_url, headers=headers, params=params, verify=False, timeout=30)
            )
        except (RuntimeError, requests.RequestException) as exc:
            logger.error("Error listing templates for repo %s (page %s): %s", repo_id, page, exc)
            break
        if response.status_code != 200:
            logger.error("Error listing templates for repo %s (page %s): %s - %s", repo_id, page, response.status_code, response.text)
            break
        try:
            data = response.json()
        except ValueError:
            logger.error("Error parsing templates response as JSON for repo %s (page %s)", repo_id, page)
            break
        items = data.get('object', [])
        if not items:
            break
        all_items.extend(items)
        # If fewer than per_page returned, likely last page
        if len(items) < per_page:
            break
        page += 1
    return all_items


def list_all_templates(fabric_host, access_token):
    """Return flattened list of all templates across repositories with repo info."""
    repos = list_repositories(fabric_host, access_token)
    results = []
    for repo in repos:
        rid = repo.get('id')
        rname = repo.get('name')
        if not rid:
            continue
        templates = list_templates_for_repo(fabric_host, access_token, rid)
        for t in templates:
            t_copy = dict(t)
            t_copy['repository_id'] = rid
            t_copy['repository_name'] = rname
            results.append(t_copy)
    return results
    if response.status_code == 200:
        try:
            data = response.json()
        except ValueError:
            logger.error("Error parsing templates response as JSON")
            return None
        for item in data.get("object", []):
            if item.get('name') == template and item.get('version') == version:
                logger.info("Template '%s' (version=%s) resolved to id %s", template, version, item.get('id'))
                return item.get('id')
        logger.info("Template '%s' (version=%s) not found", template, version)
        return None
    else:
        logger.error("Error listing templates: %s - %s", response.status_code, response.text)
        return None


def download_template(fabric_host, access_token, template_id):
    logger.info("Downloading template documentation for id %s on host %s", template_id, fabric_host)
    url = f"https://{fabric_host}/api/v1/system/repository/template/documentation/{template_id}:download"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Cache-Control": "no-cache"
    }
    data = {
        "interactive": False
    }
    try:
        response = requests.post(url, headers=headers, json=data, verify=False, timeout=30)
    except requests.RequestException as exc:
        logger.error("Error downloading template %s: %s", template_id, exc)
        return None
    if response.status_code == 200:
        check_tasks(fabric_host, access_token)
        logger.info("Template %s downloaded successfully", template_id)
        return None
    else:
        logger.error("Error downloading template %s: %s - %s", template_id, response.status_code, response.text)
        return None


def create_fabric(fabric_host, access_token, template_id, template, version):
    """
    Create fabric from template (asynchronous).
    Returns immediately after initiating the create task.
    """
    logger.info("Initiating fabric creation from template_id %s on host %s", template_id, fabric_host)
    url = (f"https://{fabric_host}/api/v1/model/fabric")
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Cache-Control": "no-cache"
    }
    data = {
        "if_exist": "rename",
        "template": template_id
    }
    try:
        response = _make_rate_limited_request(
            fabric_host,
            lambda: requests.post(url, headers=headers, json=data, verify=False, timeout=180)  # 3 minutes for fabric creation
        )
    except RuntimeError as exc:
        logger.error("Error initiating fabric creation for template %s: %s", template_id, exc)
        return (False, [f"Request error: {str(exc)}"])
    except requests.RequestException as exc:
        logger.error("Error initiating fabric creation for template %s: %s", template_id, exc)
        return (False, [f"Request error: {str(exc)}"])
    if response.status_code == 200:
        logger.info("Fabric creation task initiated successfully (async)")
        return (True, [])
    else:
        error_msg = f"Error initiating fabric creation for template {template_id}: {response.status_code} - {response.text}"
        logger.error(error_msg)
        return (False, [error_msg])


def install_fabric(fabric_host, access_token, template, version):
    logger.info("Installing fabric '%s' version %s on host %s", template, version, fabric_host)
    # List all fabrics instead of using select (more reliable)
    # The select parameter might not work correctly, so we'll filter client-side
    url_fabric_id = f"https://{fabric_host}/api/v1/model/fabric"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Cache-Control": "no-cache"
    }
    try:
        response = requests.get(url_fabric_id, headers=headers, verify=False, timeout=30)
    except requests.RequestException as exc:
        logger.error("Error finding fabric by name: %s", exc)
        return (False, [f"Request error finding fabric: {str(exc)}"])
    if response.status_code != 200:
        error_msg = f"Error finding fabric by name: {response.status_code} - {response.text}"
        logger.error(error_msg)
        return (False, [error_msg])
    try:
        data = response.json()
    except ValueError:
        error_msg = "Error parsing fabric list response as JSON"
        logger.error(error_msg)
        return (False, [error_msg])
    objects = data.get('object', [])
    
    # Filter fabrics by both name (case-insensitive) and version
    template_name_lower = (template or "").strip().lower()
    matching_fabrics = []
    for item in objects:
        item_name = (item.get('name') or "").strip().lower()
        item_version = item.get('version')
        if item_name == template_name_lower and item_version == version:
            matching_fabrics.append(item)
    
    if not matching_fabrics:
        # No fabric found with matching name and version
        # Check if fabric exists with different version
        fabrics_with_name = [item for item in objects if (item.get('name') or "").strip().lower() == template_name_lower]
        if fabrics_with_name:
            available_versions = [item.get('version') for item in fabrics_with_name if item.get('version')]
            if available_versions:
                error_msg = f"Fabric '{template}' found but version '{version}' not found. Available versions: {', '.join(str(v) for v in available_versions)}"
            else:
                error_msg = f"Fabric '{template}' found but has no version information"
        else:
            # List some available fabric names for debugging
            available_names = [item.get('name') for item in objects[:10] if item.get('name')]
            if available_names:
                error_msg = f"Fabric '{template}' not found. Sample of available fabrics: {', '.join(available_names)}"
            else:
                error_msg = f"Fabric '{template}' not found. No fabrics available on this host."
        logger.error(error_msg)
        return (False, [error_msg])
    
    # If multiple fabrics match, prefer the most recently created one
    # Sort by ID descending (assuming higher IDs are newer)
    matching_fabrics.sort(key=lambda x: x.get('id', 0), reverse=True)
    fabric_id = matching_fabrics[0].get('id')
    
    if not fabric_id:
        error_msg = f"Fabric '{template}' v{version} found but has no ID"
        logger.error(error_msg)
        return (False, [error_msg])
    
    logger.info("Resolved fabric id %s for installation", fabric_id)
    
    # Verify fabric still exists before attempting installation
    url_verify = f"https://{fabric_host}/api/v1/model/fabric/{fabric_id}"
    try:
        verify_response = requests.get(url_verify, headers=headers, verify=False, timeout=30)
        if verify_response.status_code != 200:
            error_msg = f"Fabric ID {fabric_id} no longer exists (may have been deleted). Status: {verify_response.status_code}"
            logger.error(error_msg)
            return (False, [error_msg])
    except requests.RequestException as exc:
        logger.warning("Could not verify fabric exists before installation: %s", exc)
        # Continue anyway - the installation request will fail if fabric doesn't exist
    
    # Capture timestamp BEFORE making the POST request
    # This ensures tasks created by the installation API call are included
    from datetime import datetime, timezone, timedelta
    install_start_time = datetime.now(timezone.utc)
    
    url_install = (f"https://{fabric_host}/api/v1/runtime/fabric/{fabric_id}")
    try:
        response = _make_rate_limited_request(
            fabric_host,
            lambda: requests.post(url_install, headers=headers, verify=False, timeout=900)  # 15 minutes for installation
        )
    except RuntimeError as exc:
        logger.error("Error installing Fabric %s: %s", fabric_id, exc)
        return (False, [f"Request error installing fabric: {str(exc)}"])
    except requests.RequestException as exc:
        logger.error("Error installing Fabric %s: %s", fabric_id, exc)
        return (False, [f"Request error installing fabric: {str(exc)}"])
    
    if response.status_code == 200:
        logger.info("Fabric installation task initiated successfully (async)")
        return (True, [])
    else:
        # Parse error response to provide better error message
        error_detail = response.text
        try:
            error_json = response.json()
            if 'detail' in error_json:
                error_detail = error_json['detail']
            elif 'errors' in error_json:
                # Check for cast errors
                errors = error_json.get('errors', {})
                if 'fabric' in errors:
                    fabric_errors = errors['fabric']
                    if isinstance(fabric_errors, list):
                        for fabric_error in fabric_errors:
                            if isinstance(fabric_error, dict) and 'cast' in fabric_error:
                                error_detail = f"Fabric ID {fabric_id} no longer exists: {fabric_error['cast']}"
                                break
        except (ValueError, KeyError):
            pass
        
        error_msg = f"Error installing Fabric {fabric_id}: {response.status_code} - {error_detail}"
        logger.error(error_msg)
        return (False, [error_msg])










