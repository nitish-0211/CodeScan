import os
import requests
from fastapi import FastAPI, Request, Depends
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from dotenv import load_dotenv
import git
import subprocess
import shutil
import json
from fastapi.staticfiles import StaticFiles
from urllib.parse import urlencode

load_dotenv()


GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")
GITHUB_REDIRECT_URI = os.getenv("GITHUB_REDIRECT_URI")

app = FastAPI()

# Templales
templates = Jinja2Templates(directory="templates")

app.mount("/static", StaticFiles(directory="static"), name="static")

CLONE_DIR = "/tmp/repos"


@app.get("/")
def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/login/github")
def github_login():
    params = {
        "client_id": GITHUB_CLIENT_ID,
        "redirect_uri": GITHUB_REDIRECT_URI,
        "scope": "repo"
    }
    github_oauth_url = f"https://github.com/login/oauth/authorize?{urlencode(params)}"
    return RedirectResponse(github_oauth_url)



@app.get("/github/callback")
def github_callback(code: str):
    token_url = "https://github.com/login/oauth/access_token"
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = {
        "client_id": GITHUB_CLIENT_ID,
        "client_secret": GITHUB_CLIENT_SECRET,
        "code": code,
        "redirect_uri": GITHUB_REDIRECT_URI
    }

    token_response = requests.post(token_url, headers=headers, data=data)

    response_json = token_response.json()
    access_token = response_json.get("access_token")
    if access_token:
        return RedirectResponse(f"/repos?access_token={access_token}")
    return {"error": "Failed to authenticate"}


# fetch the user's public and private repositories along with the owner, name, visibility, and primary language to the template

@app.get("/repos")
def list_user_repos(request: Request, access_token: str):
    repos_url = "https://api.github.com/user/repos"
    headers = {"Authorization": f"token {access_token}"}
    response = requests.get(repos_url, headers=headers)

    if response.status_code == 200:
        repos = response.json()
        
        repo_details = [
            {
                "owner": repo["owner"]["login"],
                "name": repo["name"],
                "private": repo["private"],
                "language": repo["language"],
                "clone_url": repo["clone_url"]
            }
            for repo in repos
        ]
        return templates.TemplateResponse("repos.html", {"request": request, "repos": repo_details, "access_token": access_token})
    return {"error": "Failed to fetch repositories"}



@app.get("/scan-repo")
async def scan_repo(access_token: str, repo_url: str):
    repo_name = repo_url.split("/")[-1].replace(".git", "")
    repo_path = os.path.join(CLONE_DIR, repo_name)

    print("repo: ", repo_path)

    if os.path.exists(repo_path):
        shutil.rmtree(repo_path)

    try:
        # Clone repo
        git.Repo.clone_from(repo_url, repo_path)
    except Exception as e:
        return {"error": f"Failed to clone repository: {str(e)}"}

    # Scanning for vulnerabilities
    scan_result = run_bandit_scan(repo_path)
    
    for file_data in scan_result.get('scan_result', {}).values():
        if 'metrics' not in file_data:
            file_data['metrics'] = {}
            file_data['results'] = []

    return {"scan_result": scan_result}



@app.get("/scan-results", response_class=HTMLResponse)
async def scan_results(request: Request, access_token: str, repo_url: str):


    """
    Get scan results from the repo and fetch repo details from the GitHub API.
    Return the formatted response for template rendering.
    """
    

    # Extract owner and repo name from the URL
    repo_name_with_owner = repo_url.split("github.com/")[-1].replace(".git", "")
    repo_owner, repo_name = repo_name_with_owner.split('/')

    repo_visibility = "Unknown"
    repo_language = "Unknown"
    
    headers = {"Authorization": f"token {access_token}"}
    repo_api_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}"
    
    # fetching repo details from GitHub API
    try:
        repo_response = requests.get(repo_api_url, headers=headers)
        
        if repo_response.status_code == 200:
            repo_data = repo_response.json()
            
            repo_visibility = "Private" if repo_data.get("private", False) else "Public"
            repo_language = repo_data.get("language", "Unknown")
        else:
            print(f"GitHub API Error: {repo_response.status_code} - {repo_response.text}")
    except Exception as e:
        print(f"Exception while fetching repo details: {str(e)}")
    
    scan_result = await scan_repo(access_token, repo_url)
    
    return templates.TemplateResponse("scan_result.html", {
        "request": request,
        "scan_result": scan_result,
        "repo_owner": repo_owner,
        "repo_name": repo_name,
        "repo_visibility": repo_visibility,
        "repo_language": repo_language,
    })


# function to find all python files in the repository

def find_python_files(repo_path: str):
    """Recursively find all Python files in the given repository path."""
    python_files = []
    print(repo_path)
    for root, dirs, files in os.walk(repo_path):
        for file in files:
            if file.endswith(".py"):
                python_files.append(os.path.join(root, file))
    print("python_files:::", python_files)
    return python_files



def run_bandit_scan(repo_path: str):
    try:
        python_files = find_python_files(repo_path)
        
        if not python_files:
            return {"error": "No Python files found in the repository."}
        
        scan_results = {}

  # recursively scanning directory
        for py_file in python_files:
            result = subprocess.run(
                ["bandit", "-r", py_file, "-f", "json"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            scan_results[py_file] = json.loads(result.stdout)
        return scan_results

    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    if not os.path.exists(CLONE_DIR):
        os.makedirs(CLONE_DIR)
    
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
