# NurseLink Security Console
AI-Powered HIPAA Incident Response Tool

## Overview
A Flask web application that analyzes security incidents for a fictional healthcare startup (NurseLink) and maps them to HIPAA Security Rule controls and NIST 800-30 risk scoring frameworks.

## Features
- AI-powered incident analysis using Groq LLaMA 3.3
- Automatic HIPAA control citation (§164.312 etc)
- NIST 800-30 likelihood and impact scoring
- SQLite audit log of all incidents
- Clean dashboard UI

## Frameworks Used
- HIPAA Security Rule (45 CFR Part 164)
- NIST 800-30 Risk Assessment Guide

## Tech Stack
- Python, Flask, SQLite, Groq API, HTML/CSS

## Setup
1. Clone the repo
2. Create virtual environment: `python -m venv venv`
3. Activate: `venv\Scripts\activate`
4. Install dependencies: `pip install flask groq python-dotenv`
5. Create `.env` file with `GROQ_API_KEY=yourkey`
<<<<<<< HEAD
6. Run: `python app.py`
=======
6. Run: `python app.py`
>>>>>>> f7830fa2ad6179a2c0ab44a48c20645bfc389df8
