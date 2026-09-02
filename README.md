🛡️ ThreatLens — AI Cybersecurity Analyzer

ThreatLens is a beginner-friendly AI cybersecurity analysis application built with Python + Streamlit.

It allows a user to analyze:

IP addresses

Domains

URLs

The application uses:

VirusTotal API for security/threat intelligence

WHOIS for domain registration information

Google Gemini API for an easy-to-understand security explanation

1. Features

🔍 Target Analysis

The user can select one of three input types:

IP Address

Domain

URL

🛡️ VirusTotal Analysis

ThreatLens retrieves available VirusTotal information such as:

Malicious detections

Suspicious detections

Harmless detections

Undetected results

Reputation score

Security vendors that flagged the target

🌐 WHOIS Information

For domains, the application can display:

Registrar

Creation date

Expiration date

Name servers

🤖 Gemini AI Insights

Gemini explains the collected findings according to the selected knowledge level:

Beginner

Intermediate

Advanced

The AI is instructed to use only the information supplied by the application and avoid claiming that a target is 100% safe or malicious without sufficient evidence.

2. Technology Stack

Technology

Purpose

Python

Main programming language

Streamlit

Web application UI

VirusTotal API

Threat intelligence

WHOIS

Domain information

Google Gemini API

AI security explanation

python-dotenv

Local API key management

Requests

HTTP/API requests

3. Project Structure

ThreatLens/
│
├── app.py
├── requirements.txt
├── .env
└── .gitignore

Important

.env contains private API keys and must not be uploaded to GitHub.

4. API Keys

The application uses two API keys:

VT_API_KEY
GEMINI_API_KEY

Local VS Code Setup

Create a .env file in the project root:

VT_API_KEY=your_virustotal_api_key
GEMINI_API_KEY=your_gemini_api_key

The application loads these values using:

from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

Never hard-code real API keys directly inside app.py.

5. .gitignore

Use this .gitignore:

.env
.streamlit/
__pycache__/

This prevents sensitive files such as .env from being committed to GitHub.

6. Requirements

Create requirements.txt:

streamlit
requests
python-whois
python-dotenv
google-generativeai

Install dependencies:

pip install -r requirements.txt

7. Run the Application Locally

Open the project folder in VS Code.

Run:

streamlit run app.py

Streamlit will normally open the application at:

http://localhost:8501

8. Application Workflow

The basic workflow is:

User
  ↓
Select Input Type
  ↓
Enter IP / Domain / URL
  ↓
Validate Input
  ↓
VirusTotal Analysis
  ↓
WHOIS Analysis
  ↓
Gemini AI Analysis
  ↓
Display Security Report

For domains:

Domain
  ↓
VirusTotal
  +
WHOIS
  ↓
Gemini
  ↓
Security Insights

For IP addresses:

IP Address
  ↓
VirusTotal
  ↓
Gemini
  ↓
Security Insights

For URLs:

URL
  ↓
VirusTotal
  ↓
Gemini
  ↓
Security Insights

9. GitHub Deployment

The recommended architecture is:

VS Code
   │
   ├── app.py
   ├── requirements.txt
   ├── .gitignore
   └── .env
          │
          │ .env is NOT uploaded
          ↓
       GitHub
   │
   ├── app.py
   ├── requirements.txt
   └── .gitignore
          │
          ↓
   Streamlit Community Cloud
          │
          └── Secrets
              ├── VT_API_KEY
              └── GEMINI_API_KEY

Create Git Repository

Inside the VS Code terminal:

git init

Add files:

git add app.py requirements.txt .gitignore

Commit:

git commit -m "Initial ThreatLens app"

Connect your GitHub repository:

git remote add origin YOUR_GITHUB_REPOSITORY_URL

Set the main branch:

git branch -M main

Push:

git push -u origin main

10. Updating GitHub After Code Changes

Whenever you modify app.py or another tracked file:

git add .
git commit -m "Update ThreatLens app"
git push origin main

The basic workflow is:

Change code
   ↓
Save
   ↓
git add .
   ↓
git commit
   ↓
git push
   ↓
GitHub updated

Do not use:

git add .env

and do not upload .env manually.

11. Streamlit Cloud Deployment

After pushing the project to GitHub:

Open Streamlit Community Cloud.

Sign in with GitHub.

Create a new app.

Select your GitHub repository.

Select the main branch.

Set the main file to:

app.py

Deploy the application.

12. Streamlit Cloud Secrets

The .env file is used for local development.

On Streamlit Cloud, add the API keys through the application's Secrets settings.

Use:

VT_API_KEY = "your_actual_virustotal_api_key"
GEMINI_API_KEY = "your_actual_gemini_api_key"

The application should load secrets in a way that supports both local development and Streamlit Cloud.

Recommended approach:

def load_secret(name):

    # Streamlit Cloud
    try:
        value = st.secrets.get(name)

        if value:
            return value
    except Exception:
        pass

    # Local VS Code .env
    return os.getenv(name)


VT_API_KEY = load_secret("VT_API_KEY")
GEMINI_API_KEY = load_secret("GEMINI_API_KEY")

This gives the application two possible sources:

Local VS Code
    ↓
.env
    ↓
os.getenv()

and:

Streamlit Cloud
    ↓
Secrets
    ↓
st.secrets

13. Security Best Practices

Never put API keys directly in code

Avoid:

VT_API_KEY = "123456789..."

Use environment variables or Streamlit Secrets instead.

Never upload .env

Your GitHub repository should look like:

ThreatLens/
│
├── app.py
├── requirements.txt
└── .gitignore

It should NOT contain:

.env

14. Error Handling

ThreatLens handles common API problems including:

Missing VirusTotal API key

Invalid VirusTotal API key

VirusTotal rate limits

Missing VirusTotal data

Network errors

WHOIS lookup failures

Gemini API failures

The application displays user-friendly messages instead of exposing sensitive information.

15. Important Security Disclaimer

ThreatLens is an intelligence-analysis tool.

Its results should not be treated as absolute proof that a target is safe or malicious.

For example:

0 malicious detections

does not automatically mean:

100% safe

Similarly, detections from security vendors should be interpreted in context.

The application should therefore communicate uncertainty honestly.

16. Recommended Final Architecture

                  ┌───────────────────┐
                  │       User        │
                  └─────────┬─────────┘
                            │
                            ↓
                  ┌───────────────────┐
                  │    Streamlit UI   │
                  └─────────┬─────────┘
                            │
                            ↓
                  ┌───────────────────┐
                  │ Input Validation  │
                  └─────────┬─────────┘
                            │
                ┌───────────┴───────────┐
                ↓                       ↓
       ┌─────────────────┐      ┌─────────────────┐
       │  VirusTotal API │      │   WHOIS Lookup  │
       └────────┬────────┘      └────────┬────────┘
                │                       │
                └───────────┬───────────┘
                            ↓
                  ┌───────────────────┐
                  │    Gemini AI      │
                  │ Security Insights │
                  └─────────┬─────────┘
                            ↓
                  ┌───────────────────┐
                  │  Final UI Report  │
                  └───────────────────┘

17. Development → Deployment Workflow

The complete development workflow is:

1. Build app in VS Code
        ↓
2. Store keys in .env
        ↓
3. Test locally
        ↓
4. Add .env to .gitignore
        ↓
5. Push code to GitHub
        ↓
6. Connect GitHub to Streamlit Cloud
        ↓
7. Add API keys to Streamlit Secrets
        ↓
8. Deploy
        ↓
9. Test live application
        ↓
10. Make changes in VS Code
        ↓
11. git add .
        ↓
12. git commit
        ↓
13. git push
        ↓
14. Streamlit Cloud updates the app

18. Troubleshooting

Error: API key is missing

Check that your local .env contains:

VT_API_KEY=your_key
GEMINI_API_KEY=your_key

For Streamlit Cloud, check the application's Secrets.

Error: VirusTotal 401

The VirusTotal key may be invalid or incorrectly configured.

Error: VirusTotal 429

The API rate limit may have been reached.

Error: Gemini error

Check:

Gemini API key

Gemini model name

Installed Google Gemini SDK

API availability

.env appears on GitHub

Stop and remove it from the repository immediately, and rotate/revoke the exposed API keys. Do not simply rely on deleting the file in a later commit because old commits may still contain the secret.

19. Project Goal

ThreatLens demonstrates how multiple APIs can be combined into one AI-powered cybersecurity application:

VirusTotal
    +
WHOIS
    +
Gemini AI
    ↓
ThreatLens
    ↓
AI-assisted cybersecurity report

The main learning concepts demonstrated by this project are:

API integration

API key management

Input validation

REST API requests

JSON response handling

AI prompting

Streamlit UI development

Git and GitHub

Cloud deployment

Environment variables

Secrets management
