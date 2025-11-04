import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import time
import sys
import itertools
import logging

logger = logging.getLogger(__name__)

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
        # Log progress when the count changes or every 10 seconds of waiting
        if current_count != previous_count or (waited - last_progress_log) >= 10:
            logger.info("Tasks running: %d, waited %ds", current_count, waited)
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
    """Return current count of running tasks without waiting."""
    url = f"https://{fabric_host}/api/v1/task?running=true"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Cache-Control": "no-cache"
    }
    try:
        response = requests.get(url, headers=headers, verify=False, timeout=15)
    except requests.RequestException as exc:
        logger.error("Error querying task status: %s", exc)
        return None
    if response.status_code != 200:
        logger.error("Task status error: %s - %s", response.status_code, response.text)
        return None
    try:
        data = response.json()
    except ValueError:
        logger.error("Task status JSON parse error")
        return None
    return data.get("page", {}).get("count", 0)


def get_recent_task_errors(fabric_host, access_token, limit=50):
    """
    Query recent completed/failed tasks and extract error information.
    Returns a list of error dictionaries with task details.
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
    
    # Filter for failed or error tasks
    for task in tasks:
        status = task.get("status", "").lower()
        task_id = task.get("id")
        task_name = task.get("name", "Unknown Task")
        
        # Check for failed status or error messages
        if status in ["failed", "error", "exception"]:
            error_msg = task.get("error", "") or task.get("message", "") or task.get("description", "")
            if error_msg:
                errors.append({
                    "task_id": task_id,
                    "task_name": task_name,
                    "status": status,
                    "error": error_msg,
                    "timestamp": task.get("created_at") or task.get("updated_at")
                })
                logger.warning("Found failed task: %s (id: %s) - %s", task_name, task_id, error_msg)
    
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
        response = requests.get(url, headers=headers, params=params, verify=False, timeout=30)
    except requests.RequestException as exc:
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
        response = requests.post(url, headers=headers, json=data, verify=False, timeout=30)
        
        # Log response details
        logger.info("Password change response - Status: %s", response.status_code)
        logger.info("Password change response - Headers: %s", dict(response.headers))
        logger.info("Password change response - Body: %s", response.text)
        
    except requests.RequestException as exc:
        logger.error("Error updating guest user password: %s", exc, exc_info=True)
        return None
    
    if response.status_code == 200:
        logger.info("Password updated for user_id %s", user_id)
        return None
    else:
        logger.error("Error updating guest user password: %s - %s", response.status_code, response.text)
        return None


def reset_fabric(fabric_host, access_token):
    logger.info("Resetting fabric on host %s", fabric_host)
    url = f"https://{fabric_host}/api/v1/runtime/fabric"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Cache-Control": "no-cache"
    }
    try:
        response = requests.delete(url, headers=headers, verify=False, timeout=30)
    except requests.RequestException as exc:
        logger.error("Error in reset Fabric: %s", exc)
        return None
    if response.status_code == 200:
        check_tasks(fabric_host, access_token)
        logger.info("Fabric reset successful")
        return None
    else:
        logger.error("Error in reset Fabric: %s - %s", response.status_code, response.text)
        return None


def batch_delete(fabric_host, access_token):
    logger.info("Deleting all fabrics in batch on host %s", fabric_host)
    url = f"https://{fabric_host}/api/v1/model/fabric/batch?interactive=false"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Cache-Control": "no-cache"
    }
    try:
        response = requests.delete(url, headers=headers, verify=False, timeout=30)
    except requests.RequestException as exc:
        logger.error("Error in batch delete: %s", exc)
        return None
    if response.status_code == 200:
        check_tasks(fabric_host, access_token)
        logger.info("Batch delete successful")
        return None
    else:
        logger.error("Error in batch delete: %s - %s", response.status_code, response.text)
        return None


def refresh_repositories(fabric_host, access_token):
    logger.info("Refreshing all remote repositories on host %s", fabric_host)
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
        logger.error("Error in refresh all repositories: %s", exc)
        return None
    if response.status_code == 200:
        check_tasks(fabric_host, access_token)
        logger.info("Refresh all repositories successful")
        return None
    else:
        logger.error("Error in refresh all repositories: %s - %s", response.status_code, response.text)
        return None


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
        response = requests.get(url, headers=headers, params=params, verify=False, timeout=30)
    except requests.RequestException as exc:
        logger.error("Error finding Repository Id: %s", exc)
        return None


def list_repositories(fabric_host, access_token):
    """Return list of remote repositories (objects)."""
    url = f"https://{fabric_host}/api/v1/system/repository/remote"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Cache-Control": "no-cache"
    }
    try:
        response = requests.get(url, headers=headers, verify=False, timeout=30)
    except requests.RequestException as exc:
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
    return data.get('object', [])
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
        logger.info("Repository '%s' resolved to id %s", repo_name, repo_id)
        return repo_id
    else:
        logger.error("Error finding Repository Id: %s - %s", response.status_code, response.text)
        return None


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
            response = requests.get(base_url, headers=headers, params=params, verify=False, timeout=30)
        except requests.RequestException as exc:
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
    logger.info("Creating fabric from template_id %s on host %s", template_id, fabric_host)
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
        response = requests.post(url, headers=headers, json=data, verify=False, timeout=30)
    except requests.RequestException as exc:
        logger.error("Error creating template %s: %s", template_id, exc)
        return (False, [f"Request error: {str(exc)}"])
    if response.status_code == 200:
        result = check_tasks(fabric_host, access_token)
        if result is None:
            logger.error("Error checking tasks after fabric creation")
            return (False, ["Error checking task status after fabric creation"])
        elapsed_time, success = result if isinstance(result, tuple) else (result, True)
        if not success:
            logger.error("Timed out waiting for tasks to finish after fabric creation")
            return (False, ["Timed out waiting for tasks to finish after 15 minutes"])
        
        # Check for task errors after tasks complete
        task_errors = get_recent_task_errors(fabric_host, access_token, limit=20)
        if task_errors:
            error_messages = [f"Task '{err['task_name']}': {err['error']}" for err in task_errors]
            logger.warning("Found %d task errors after fabric creation", len(task_errors))
            return (False, error_messages)
        
        logger.info("Fabric created from template_id %s", template_id)
        return (True, [])
    else:
        error_msg = f"Error creating template {template_id}: {response.status_code} - {response.text}"
        logger.error(error_msg)
        return (False, [error_msg])


def install_fabric(fabric_host, access_token, template,version):
    logger.info("Installing fabric '%s' version %s on host %s", template, version, fabric_host)
    url_fabric_id = (f"https://{fabric_host}/api/v1/model/fabric?select=name={template}")
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
    fabric_id = next((item.get('id') for item in objects if item.get('version') == version), None)
    if fabric_id:
        logger.info("Resolved fabric id %s for installation", fabric_id)
        url_install = (f"https://{fabric_host}/api/v1/runtime/fabric/{fabric_id}")
        try:
            response = requests.post(url_install, headers=headers, verify=False, timeout=30)
        except requests.RequestException as exc:
            logger.error("Error installing Fabric %s: %s", fabric_id, exc)
            return (False, [f"Request error installing fabric: {str(exc)}"])
        if response.status_code == 200:
            result = check_tasks(fabric_host, access_token)
            if result is None:
                logger.error("Error checking tasks after installation")
                return (False, ["Error checking task status after installation"])
            elapsed_time, success = result if isinstance(result, tuple) else (result, True)
            if not success:
                logger.error("Timed out waiting for tasks to finish after installation")
                return (False, ["Timed out waiting for tasks to finish after 15 minutes"])
            
            # Check for task errors after tasks complete
            task_errors = get_recent_task_errors(fabric_host, access_token, limit=20)
            if task_errors:
                error_messages = [f"Task '{err['task_name']}': {err['error']}" for err in task_errors]
                logger.warning("Found %d task errors after fabric installation", len(task_errors))
                return (False, error_messages)
            
            logger.info("Fabric %s installed successfully", fabric_id)
            return (True, [])
        else:
            error_msg = f"Error installing Fabric {fabric_id}: {response.status_code} - {response.text}"
            logger.error(error_msg)
            return (False, [error_msg])
    else:
        error_msg = "No valid fabric_id found for installation. Version mismatch or fabric missing"
        logger.info(error_msg)
        return (False, [error_msg])










