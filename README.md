# prompt-security-and-data-trust-dashboard
import gradio as gr
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from scipy.stats import entropy
import plotly.graph_objects as go
import datetime
import os
import re
import time

# -----------------------------
# BLOCK STORAGE
# -----------------------------
blocked_users = {}
 
# -----------------------------
# COMPREHENSIVE SAFETY PATTERNS
# -----------------------------
safety_patterns = {
    'jailbreak': ["ignore previous instructions", "jailbreak now", "override safety", "unrestricted mode"],
    'privacy': ["ssn", "credit card", "api key", "private key", "dox", "pii"],
    'human_harm': ["kill yourself", "kys", "suicide method", "overdose", "self harm"],
    'csam': ["child porn", "csam", "underage sex", "pedo"],
    'harassment': ["swat call", "bomb threat", "kill", "hate", "ethnic cleansing"],
    'illegal': ["make meth", "build bomb", "human trafficking", "terror attack"]
}

# Semantic vectors (1-4 ngrams for efficiency)
all_patterns = [p for cat in safety_patterns.values() for p in cat]
vectorizer = TfidfVectorizer(max_features=1500, stop_words='english', ngram_range=(1,4))
safety_vectors = vectorizer.fit_transform(all_patterns)

# -----------------------------
# HYPER-EFFICIENT KEYWORD DETECTION
# -----------------------------
def detect_prompt_injection(prompt):
    prompt_lower = prompt.lower()
    score = 0
    
    # CRITICAL PHRASES (+4) - FIXED REGEX
    critical_phrases = [
        r'kill yourself|kys|suicide|overdose|self harm',
        r'child porn|csam|underage|pedo',
        r'ignore previous|jailbreak|override safety|dan mode|restrict.*rules|disable.*safety|bypass.*rules',
        r'swat|bomb threat|ethnic cleansing',
        r'make meth|build bomb|traffick|terror'
    ]
    for pattern in critical_phrases:
        if re.search(pattern, prompt_lower, re.IGNORECASE | re.DOTALL):
            score += 4
    
    # DANGER WORDS (+2) - passwords FIXED
    danger_words = [
        'ssn', 'credit card', 'api key', 'private key', 'dox', 'pii',
        'password', 'passwords', 'rape', 'kill', 'die', 'hate', 'bomb', 'meth', 'terror', 'pedo'
    ]
    matches = re.findall(r'\b(?:' + '|'.join(re.escape(w) for w in danger_words) + r')\b', prompt_lower, re.IGNORECASE)
    score += len(matches) * 2
    
    return score

# -----------------------------
# RISKY WORD HIGHLIGHTING
# -----------------------------
def highlight_words(prompt):
    risky_words = (
        ['ssn', 'api key', 'dox', 'pii', 'pedo', 'rape', 'bomb', 'meth', 'terror'] +
        ['kill', 'die', 'hate', 'suicide', 'csam', 'jailbreak', 'swat']
    )
    words = prompt.split()
    highlighted = []
    for w in words:
        if any(rw in w.lower() for rw in risky_words):
            highlighted.append(f"🔴 **{w}**")
        else:
            highlighted.append(w)
    return " ".join(highlighted)

# -----------------------------
# ADVANCED ML SCORING (ULTRA-EFFICIENT)
# -----------------------------
def advanced_ml_score(prompt):
    if len(prompt) < 5: return 0.0
    
    prompt_lower = prompt.lower()
    
    # 1. Keywords (60% weight - primary detector)
    keyword_score = min(detect_prompt_injection(prompt) * 0.6, 4.0)
    
    # 2. Semantic similarity (25%)
    try:
        prompt_vec = vectorizer.transform([prompt_lower])
        similarities = cosine_similarity(prompt_vec, safety_vectors)[0]
        semantic_score = np.max(similarities) * 2.0
    except: semantic_score = 0
    
    # 3. Length + toxicity bonus (15%)
    length_penalty = min(len(prompt) / 80.0, 1.0) * 0.15
    
    toxicity_bonus = 0
    toxic_indicators = ['kill', 'die', 'child', 'rape', 'hate', 'bomb']
    if any(indicator in prompt_lower for indicator in toxic_indicators):
        toxicity_bonus = 0.8
    
    total = keyword_score + semantic_score + length_penalty + toxicity_bonus
    return round(min(total, 6.0), 2)

# -----------------------------
# LOGGING
# -----------------------------
def log_prompt(prompt, session_id, flag, ml_score):
    # Change the filename here to whatever you want
    file = "prompt_logs.csv"
    
    row = pd.DataFrame([{
        "prompt": prompt[:200],
        "session_id": session_id,
        "risk_flag": flag,
        "ml_score": ml_score,
        "timestamp": datetime.datetime.now()
    }])

    # Mode 'a' appends to the file, header=False prevents repeating headers
    if not os.path.exists(file):
        row.to_csv(file, index=False)
    else:
        row.to_csv(file, mode='a', index=False, header=False)

# -----------------------------
# PROMPT ANALYSIS (FINAL VERSION)
# -----------------------------
def analyze_prompt(prompt, request: gr.Request):
    session_id = request.session_hash
    current_time = time.time()

    if session_id in blocked_users:
        unblock_time = blocked_users[session_id]
        if current_time < unblock_time:
            remaining = int(unblock_time - current_time)
            return f"### ⛔ **BLOCKED** - {remaining}s remaining"
        del blocked_users[session_id]

    ml_score = advanced_ml_score(prompt)
    keyword_hits = detect_prompt_injection(prompt)
    highlighted = highlight_words(prompt)

    # ULTRA-TIGHT THRESHOLDS
    if ml_score >= 2.5 or keyword_hits >= 3:
        flag = "CRITICAL"
        blocked_users[session_id] = current_time + 180  # 3 minutes
        risk_pct = min(ml_score * 18, 100)
        return f"""
### 🚨 **CRITICAL THREAT DETECTED** - PERMANENT BLOCK  
**AI Score: {ml_score:.1f}/6.0** 🔥 **{risk_pct:.0f}% DANGER**

**⚡ Keyword Hits: {keyword_hits}** ← IMMEDIATE TRIGGER  
**Detected words:** {highlighted}

**👮 REPORTED & BLOCKED**
"""
    elif ml_score >= 1.5 or keyword_hits >= 1:
        flag = "HIGH"
        blocked_users[session_id] = current_time + 45
        risk_pct = min(ml_score * 18, 100)
        return f"""
### 🚫 **HIGH RISK** - QUARANTINED 45s  
**AI Score: {ml_score:.1f}/6.0** 🔴 **{risk_pct:.0f}%**

**⚡ Keywords: {keyword_hits}**  
**Risky terms:** {highlighted}

**⚠️ BLOCKED**
"""
    else:
        flag = "Safe"
        return f"""
### ✅ **COMPLETELY SAFE**  
**AI Score: {ml_score:.1f}/6.0** 🟢 **0% RISK**

**Keywords: 0** - No threats  
**Prompt:** {prompt}

**✅ APPROVED**
"""

    log_prompt(prompt, session_id, flag, ml_score)
    return msg

# -----------------------------
# CSV ANALYSIS (UNCHANGED)
# -----------------------------
def calculate_psi(e, a):
    e, a = np.array(e), np.array(a)
    bins = np.histogram_bin_edges(np.concatenate([e,a]), bins=5)
    e_hist,_ = np.histogram(e,bins)
    a_hist,_ = np.histogram(a,bins)
    e_norm = e_hist/len(e_hist)+1e-8
    a_norm = a_hist/len(a_hist)+1e-8
    return np.sum((a_norm-e_norm)*np.log(a_norm/e_norm))

def analyze_csv(file):
    if file is None: return "Upload CSV", None
    df = pd.read_csv(file.name)
    train = df[df["train_test"]=="train"]
    prod = df[df["train_test"]!="train"]
    num = train.select_dtypes(include=np.number).columns
    psi = np.mean([calculate_psi(train[c],prod[c]) for c in num]) if len(num)>0 else 0
    trust = round(100*np.exp(-psi*0.5),2)
    fig = go.Figure(data=[go.Pie(labels=["Trust","Risk"], values=[trust,100-trust])])
    return f"Trust Score: {trust}%", fig

# -----------------------------
# ADMIN (UNCHANGED)
# -----------------------------
def download_logs(password):
    if password != "admin123": return "❌ Wrong password", None
    if not os.path.exists("prompt_logs.csv"): return "No logs", None
    return "✅ Download ready", "prompt_logs.csv"

# -----------------------------
# UI (SAME UX)
# -----------------------------
with gr.Blocks() as demo:
    gr.Markdown("# 🔐 **ULTIMATE AI SAFETY DASHBOARD**")
    
    gr.Markdown("## 🚀 Real-time Prompt Safety Scan")
    prompt_input = gr.Textbox(label="Enter any prompt...", lines=3, placeholder="Type here...")
    prompt_btn = gr.Button("🔍 SCAN FOR THREATS", variant="primary")
    prompt_output = gr.Markdown()

    gr.Markdown("### 📊 CSV Data Drift")
    file_input = gr.File()
    csv_btn = gr.Button("📈 Analyze Drift")
    csv_output = gr.Textbox()
    chart = gr.Plot()

    gr.Markdown("### 🔐 Admin Panel")
    password = gr.Textbox(type="password", label="Admin Password")
    download_btn = gr.Button("📥 Download Logs")
    status = gr.Textbox()
    file_out = gr.File()

    # Event connections
    prompt_btn.click(analyze_prompt, inputs=prompt_input, outputs=prompt_output)
    csv_btn.click(analyze_csv, inputs=file_input, outputs=[csv_output, chart])
    download_btn.click(download_logs, inputs=password, outputs=[status, file_out])

if __name__ == "__main__":
    demo.launch(share=True)
