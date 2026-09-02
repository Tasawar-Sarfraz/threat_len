"""
ThreatLens - AI Cybersecurity Analysis Application
VS Code + Streamlit Version
"""

# =========================================================
# 1. IMPORTS
# =========================================================

import os
import re
import base64
import ipaddress
import time

import requests
import streamlit as st
import whois
import google.generativeai as genai
from dotenv import load_dotenv


# =========================================================
# 2. CONFIGURATION
# =========================================================

APP_TITLE = "🛡️ ThreatLens - AI Cybersecurity Analyzer"

VT_BASE_URL = "https://www.virustotal.com/api/v3"

GEMINI_MODEL_NAME = "gemini-3.6-flash"

INPUT_TYPES = [
    "IP Address",
    "Domain",
    "URL"
]

KNOWLEDGE_LEVELS = [
    "Beginner",
    "Intermediate",
    "Advanced"
]


# =========================================================
# 3. LOAD API KEYS FROM .ENV
# =========================================================
from dotenv import load_dotenv

load_dotenv()

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

# =========================================================
# 4. HELPER FUNCTIONS
# =========================================================

def safe_get(dictionary, keys, default="Not available"):

    current = dictionary

    for key in keys:

        if isinstance(current, dict) and key in current:
            current = current[key]

        else:
            return default

    return current


def url_to_vt_id(url):

    encoded_bytes = base64.urlsafe_b64encode(
        url.encode()
    )

    encoded_str = encoded_bytes.decode().strip("=")

    return encoded_str


# =========================================================
# 5. INPUT VALIDATION
# =========================================================

def is_valid_ip(value):

    try:

        ipaddress.ip_address(value)

        return True

    except ValueError:

        return False


def is_valid_domain(value):

    domain_pattern = (
        r"^(?!-)"
        r"[A-Za-z0-9-]{1,63}"
        r"(?<!-)"
        r"(\.[A-Za-z0-9-]{1,63})+$"
    )

    return re.match(
        domain_pattern,
        value
    ) is not None


def is_valid_url(value):

    url_pattern = r"^https?://[^\s/$.?#].[^\s]*$"

    return re.match(
        url_pattern,
        value
    ) is not None


def validate_input(input_type, value):

    value = value.strip()

    if value == "":

        return False, "⚠️ Please enter a value before analyzing."


    if input_type == "IP Address":

        if not is_valid_ip(value):

            return False, "⚠️ This does not look like a valid IP address."


    if input_type == "Domain":

        if not is_valid_domain(value):

            return False, (
                "⚠️ This does not look like a valid domain. "
                "Example: google.com"
            )


    if input_type == "URL":

        if not is_valid_url(value):

            return False, (
                "⚠️ This does not look like a valid URL. "
                "It must start with http:// or https://"
            )


    return True, ""


# =========================================================
# 6. VIRUSTOTAL
# =========================================================

def get_virustotal_report(
    input_type,
    target,
    api_key
):

    if not api_key:

        return {
            "error":
            "VirusTotal API key is missing. "
            "Please add VT_API_KEY to your .env file."
        }


    headers = {
        "x-apikey": api_key
    }


    try:

        # -------------------------------------------------
        # IP ADDRESS
        # -------------------------------------------------

        if input_type == "IP Address":

            url = (
                f"{VT_BASE_URL}/ip_addresses/"
                f"{target}"
            )

            response = requests.get(
                url,
                headers=headers,
                timeout=20
            )


        # -------------------------------------------------
        # DOMAIN
        # -------------------------------------------------

        elif input_type == "Domain":

            url = (
                f"{VT_BASE_URL}/domains/"
                f"{target}"
            )

            response = requests.get(
                url,
                headers=headers,
                timeout=20
            )


        # -------------------------------------------------
        # URL
        # -------------------------------------------------

        else:

            url_id = url_to_vt_id(target)

            report_url = (
                f"{VT_BASE_URL}/urls/"
                f"{url_id}"
            )

            response = requests.get(
                report_url,
                headers=headers,
                timeout=20
            )


            # URL not found → submit it
            if response.status_code == 404:

                submit_url = (
                    f"{VT_BASE_URL}/urls"
                )

                submit_response = requests.post(
                    submit_url,
                    headers=headers,
                    data={"url": target},
                    timeout=20
                )


                if submit_response.status_code not in [200, 201]:

                    return {
                        "error":
                        "VirusTotal could not submit this URL."
                    }


                # Give VirusTotal some time
                time.sleep(15)


                response = requests.get(
                    report_url,
                    headers=headers,
                    timeout=20
                )


        # -------------------------------------------------
        # ERROR HANDLING
        # -------------------------------------------------

        if response.status_code == 401:

            return {
                "error":
                "VirusTotal API key seems invalid. "
                "Please check your .env file."
            }


        if response.status_code == 429:

            return {
                "error":
                "VirusTotal rate limit reached. "
                "Please wait and try again."
            }


        if response.status_code == 404:

            return {
                "error":
                "No VirusTotal data found for this target yet."
            }


        if response.status_code != 200:

            return {
                "error":
                f"VirusTotal returned an unexpected "
                f"error (status {response.status_code})."
            }


        # -------------------------------------------------
        # READ RESPONSE
        # -------------------------------------------------

        data = response.json()


        stats = safe_get(
            data,
            [
                "data",
                "attributes",
                "last_analysis_stats"
            ],
            {}
        )


        reputation = safe_get(
            data,
            [
                "data",
                "attributes",
                "reputation"
            ],
            "Not available"
        )


        analysis_results = safe_get(
            data,
            [
                "data",
                "attributes",
                "last_analysis_results"
            ],
            {}
        )


        # -------------------------------------------------
        # FLAGGED VENDORS
        # -------------------------------------------------

        flagged_vendors = []


        for vendor_name, vendor_result in analysis_results.items():

            category = vendor_result.get(
                "category",
                ""
            )


            if category in [
                "malicious",
                "suspicious"
            ]:

                flagged_vendors.append(
                    f"{vendor_name} ({category})"
                )


        # -------------------------------------------------
        # SUMMARY
        # -------------------------------------------------

        summary = {

            "malicious_count":
                stats.get("malicious", 0),

            "suspicious_count":
                stats.get("suspicious", 0),

            "harmless_count":
                stats.get("harmless", 0),

            "undetected_count":
                stats.get("undetected", 0),

            "reputation":
                reputation,

            "flagged_vendors":
                flagged_vendors
        }


        return summary


    except requests.exceptions.RequestException:

        return {
            "error":
            "Network error while contacting VirusTotal. "
            "Please check your internet connection."
        }


    except Exception as e:

        return {
            "error":
            f"Something went wrong while reading "
            f"the VirusTotal response: {str(e)}"
        }


# =========================================================
# 7. WHOIS
# =========================================================

def get_whois_info(domain):

    try:

        info = whois.whois(domain)


        def first_if_list(value):

            if isinstance(value, list) and len(value) > 0:

                return value[0]

            return value


        whois_summary = {

            "registrar":
                first_if_list(
                    info.registrar
                ) or "Not available",


            "creation_date":
                str(
                    first_if_list(
                        info.creation_date
                    )
                ) or "Not available",


            "expiration_date":
                str(
                    first_if_list(
                        info.expiration_date
                    )
                ) or "Not available",


            "name_servers":
                info.name_servers
                if info.name_servers
                else "Not available"
        }


        return whois_summary


    except Exception:

        return {
            "error":
            "WHOIS information could not be retrieved "
            "for this domain."
        }


# =========================================================
# 8. GEMINI PROMPT
# =========================================================

def build_gemini_prompt(
    input_type,
    target,
    knowledge_level,
    vt_summary,
    whois_summary
):

    prompt = f"""
You are a cybersecurity assistant.

Explain the security findings below to a user.

User knowledge level:
{knowledge_level}

Target analyzed:
{target}

Target type:
{input_type}


VirusTotal findings:
{vt_summary}


WHOIS findings:
{whois_summary}


Instructions:

1. Clearly state what was analyzed.

2. Explain what the VirusTotal results mean.

3. Explain suspicious or malicious findings.

4. If WHOIS information is available, explain it simply.

5. Only use the information provided above.

6. Do not invent security findings.

7. Do not claim that a target is 100% safe.

8. Do not claim that a target is 100% malicious unless the
   provided data clearly supports that conclusion.

9. If the information is limited, clearly say so.

10. Match the explanation to the user's knowledge level.

Beginner:
Use very simple language.

Intermediate:
Use useful cybersecurity terms and explain them briefly.

Advanced:
Provide a more technical interpretation.
"""

    return prompt


# =========================================================
# 9. GEMINI
# =========================================================

def get_gemini_insights(
    input_type,
    target,
    knowledge_level,
    vt_summary,
    whois_summary,
    api_key
):

    if not api_key:

        return (
            "⚠️ Gemini API key is missing. "
            "Please add GEMINI_API_KEY to your .env file."
        )


    try:

        genai.configure(
            api_key=api_key
        )


        model = genai.GenerativeModel(
            GEMINI_MODEL_NAME
        )


        prompt = build_gemini_prompt(
            input_type,
            target,
            knowledge_level,
            vt_summary,
            whois_summary
        )


        response = model.generate_content(
            prompt
        )


        if response and response.text:

            return response.text


        return (
            "⚠️ Gemini did not return an explanation. "
            "Please try again."
        )


    except Exception as e:

        return (
            "⚠️ Something went wrong while contacting "
            f"Gemini AI: {str(e)}"
        )


# =========================================================
# 10. STREAMLIT UI
# =========================================================

def render_ui():

    st.set_page_config(
        page_title="ThreatLens",
        page_icon="🛡️",
        layout="wide"
    )


    st.title(APP_TITLE)


    st.write(
        "Analyze an IP address, domain, or URL "
        "using VirusTotal, WHOIS, and Gemini AI."
    )


    input_type = st.selectbox(
        "Input Type",
        INPUT_TYPES
    )


    knowledge_level = st.selectbox(
        "Knowledge Level",
        KNOWLEDGE_LEVELS
    )


    target = st.text_input(
        f"Enter the {input_type} you want to analyze"
    )


    analyze_clicked = st.button(
        "🔍 Analyze"
    )


    return (
        input_type,
        knowledge_level,
        target,
        analyze_clicked
    )


# =========================================================
# 11. DISPLAY RESULTS
# =========================================================

def display_results(
    input_type,
    target,
    vt_summary,
    whois_summary,
    gemini_text
):

    st.subheader(
        "1. Target Information"
    )


    st.write(
        f"**Type:** {input_type}"
    )


    st.write(
        f"**Target:** {target}"
    )


    # =====================================================
    # VIRUSTOTAL
    # =====================================================

    st.subheader(
        "2. VirusTotal Results"
    )


    if "error" in vt_summary:

        st.warning(
            vt_summary["error"]
        )


    else:

        col1, col2, col3, col4 = st.columns(4)


        col1.metric(
            "🔴 Malicious",
            vt_summary["malicious_count"]
        )


        col2.metric(
            "🟠 Suspicious",
            vt_summary["suspicious_count"]
        )


        col3.metric(
            "🟢 Harmless",
            vt_summary["harmless_count"]
        )


        col4.metric(
            "⚪ Undetected",
            vt_summary["undetected_count"]
        )


        st.write(
            f"**Reputation score:** "
            f"{vt_summary['reputation']}"
        )


        if vt_summary["flagged_vendors"]:

            st.write(
                "**Vendors that flagged this target:**"
            )


            for vendor in vt_summary[
                "flagged_vendors"
            ]:

                st.write(
                    f"- {vendor}"
                )


        else:

            st.write(
                "No security vendors flagged this target."
            )


    # =====================================================
    # WHOIS
    # =====================================================

    if input_type == "Domain":

        st.subheader(
            "3. WHOIS Information"
        )


        if "error" in whois_summary:

            st.info(
                whois_summary["error"]
            )


        else:

            st.write(
                f"**Registrar:** "
                f"{whois_summary['registrar']}"
            )


            st.write(
                f"**Creation Date:** "
                f"{whois_summary['creation_date']}"
            )


            st.write(
                f"**Expiration Date:** "
                f"{whois_summary['expiration_date']}"
            )


            st.write(
                f"**Name Servers:** "
                f"{whois_summary['name_servers']}"
            )


    # =====================================================
    # GEMINI
    # =====================================================

    st.subheader(
        "4. Gemini Security Insights"
    )


    st.markdown(
        gemini_text
    )


    # =====================================================
    # OVERALL
    # =====================================================

    st.subheader(
        "5. Overall Interpretation"
    )


    st.info(
        "This report is based only on the available "
        "intelligence data. It is not guaranteed proof "
        "that a target is safe or malicious."
    )


# =========================================================
# 12. MAIN WORKFLOW
# =========================================================

def main():

    (
        input_type,
        knowledge_level,
        target,
        analyze_clicked
    ) = render_ui()


    if analyze_clicked:

        target = target.strip()


        # -------------------------------------------------
        # VALIDATE INPUT
        # -------------------------------------------------

        is_valid, error_message = validate_input(
            input_type,
            target
        )


        if not is_valid:

            st.error(
                error_message
            )

            return


        # -------------------------------------------------
        # VIRUSTOTAL
        # -------------------------------------------------

        with st.spinner(
            "Checking VirusTotal..."
        ):

            vt_summary = get_virustotal_report(
                input_type,
                target,
                VT_API_KEY
            )


        # -------------------------------------------------
        # WHOIS
        # -------------------------------------------------

        whois_summary = {}


        if input_type == "Domain":

            with st.spinner(
                "Checking WHOIS..."
            ):

                whois_summary = get_whois_info(
                    target
                )


        # -------------------------------------------------
        # GEMINI
        # -------------------------------------------------

        with st.spinner(
            "Asking Gemini AI for insights..."
        ):

            gemini_text = get_gemini_insights(
                input_type,
                target,
                knowledge_level,
                vt_summary,
                whois_summary,
                GEMINI_API_KEY
            )


        # -------------------------------------------------
        # DISPLAY
        # -------------------------------------------------

        display_results(
            input_type,
            target,
            vt_summary,
            whois_summary,
            gemini_text
        )


# =========================================================
# 13. RUN APP
# =========================================================

if __name__ == "__main__":
    main()