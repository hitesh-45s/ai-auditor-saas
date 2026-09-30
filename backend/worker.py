"""
The 0.1% God-Tier Factory Worker V2.
Implements a Recursive Spider to deep-crawl websites using a Fast Lane architecture.
Forces Gemini to pinpoint exact URLs and bugs in a structured Vulnerability Array.
Includes Multi-Model Fallback, Groq Backup AI, Issue-Specific Screenshots, Core Web Vitals, and Enterprise Exponential Backoff.
"""
import os
import time
from datetime import datetime, timezone
import json
import asyncio
import socket
from urllib.parse import urljoin, urlparse
from dotenv import load_dotenv
from upstash_redis import Redis
from supabase import create_client, Client
from google import genai
from google.genai import types
from groq import Groq
from playwright.sync_api import sync_playwright
import httpx
from bs4 import BeautifulSoup

# pylint: disable=broad-exception-caught

# Load environment variables
load_dotenv(dotenv_path="../.env")

# 1. Connect to Upstash (The Conveyor Belt)
REDIS_URL = os.getenv("UPSTASH_REDIS_REST_URL")
REDIS_TOKEN = os.getenv("UPSTASH_REDIS_REST_TOKEN")
REDIS_CLIENT = Redis(url=REDIS_URL, token=REDIS_TOKEN)

# 2. Connect to Supabase (The Vault)
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_KEY")
SUPABASE_CLIENT: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# 3. Connect the Modern Gemini Brain
GEMINI_KEY = os.getenv("GEMINI_API_KEY")
ai_client = genai.Client(api_key=GEMINI_KEY)

# 4. Connect Groq Backup AI (Zero-Downtime Guarantee)
GROQ_KEY = os.getenv("GROQ_API_KEY")
groq_client = Groq(api_key=GROQ_KEY) if GROQ_KEY else None

# ==========================================
# THE 0.1% CONFIGURATION (Optimized for Free-Tier Stability)
# ==========================================
MAX_PAGES_TO_CRAWL = 40 
THROTTLE_SLEEP_SECONDS = 1.0
AI_MAX_RETRIES = 5 # The Heavy-Duty Battering Ram


# Multi-Model Fallback Chain (provider, model) — tried in exact order listed
# gemini-2.5-flash → llama-3.3-70b → gemini-3.5-flash → gemini-2.5-flash-lite → qwen3-32b
AI_CHAIN = [
    ("gemini", "gemini-2.5-flash"),
    ("groq",   "llama-3.3-70b-versatile"),
    ("gemini", "gemini-3.5-flash"),
    ("gemini", "gemini-2.5-flash-lite"),
    ("groq",   "qwen/qwen3-32b"),
]

print("🕷️ Bulletproof Forensic Spider V2 started. Staring at the queue...")
if groq_client:
    print("✅ Groq Backup AI is ARMED and ready (llama-3.3-70b).")
else:
    print("⚠️ Groq Backup AI not configured (add GROQ_API_KEY to .env to enable).")

def is_safe_url(url):
    """Prevents Server-Side Request Forgery (SSRF) against internal networks."""
    try:
        hostname = urlparse(url).hostname
        if not hostname: return False
        ip = socket.gethostbyname(hostname)
        if ip.startswith('127.') or ip.startswith('10.') or ip.startswith('169.254.') or ip.startswith('192.168.'):
            return False
        return True
    except:
        return False

def is_valid_internal_link(base_url, link_url):
    """The Normalizer: Ensures we only crawl internal pages, no external sites or junk links."""
    parsed_base = urlparse(base_url)
    parsed_link = urlparse(link_url)
    
    if not link_url or link_url.startswith(('mailto:', 'tel:', 'javascript:')):
        return False
    if parsed_link.netloc and parsed_link.netloc != parsed_base.netloc:
        return False
        
    return is_safe_url(link_url)


async def async_deep_crawl(target_url, max_pages):
    """The Fast Lane: Asynchronously crawls multiple pages at once to save massive amounts of time."""
    visited_urls = set()
    queue = [target_url]
    
    parsed_target = urlparse(target_url)
    base_domain = f"{parsed_target.scheme}://{parsed_target.netloc}"
    aggregated_website_data = ""
    
    # We use a single async client session for connection pooling and speed
    async with httpx.AsyncClient(headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}, timeout=15.0, follow_redirects=True) as client:
        while queue and len(visited_urls) < max_pages:
            # Process URLs in small batches concurrently
            batch = queue[:5] 
            queue = queue[5:]
            tasks = []
            
            for current_url in batch:
                if current_url not in visited_urls:
                    visited_urls.add(current_url)
                    tasks.append(client.get(current_url))
                    
            if not tasks: 
                continue
            
            # Execute batch concurrently
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            
            for i, response in enumerate(responses):
                current_url = batch[i]
                
                if isinstance(response, Exception):
                    print(f"   ⚠️ Could not read {current_url}: {response}")
                    continue
                    
                if response.status_code == 200:
                    try:
                        soup = BeautifulSoup(response.text, "html.parser")
                        
                        # 1. Remove all noise
                        for element in soup(["script", "style", "video"]):
                            element.extract()
                            
                        # 2. Replace SVG math with placeholder
                        for shape in soup.find_all(["path", "polygon", "polyline", "g"]):
                            shape.replace_with("<!-- SVG_PATHS_COMPRESSED -->")

                        # 3. SMART EXTRACTION: Pull structured audit-critical sections
                        audit_data = ""

                        # HTML Lang & Document Config
                        html_lang = soup.html.get("lang") if soup.html else None
                        audit_data += f"[HTML ROOT]: lang='{html_lang or 'NOT_SPECIFIED'}'\n"

                        # Title & SEO Metadata (Canonical, OG, Twitter, Meta Description)
                        page_title = soup.title.string.strip() if soup.title and soup.title.string else "MISSING"
                        canonicals = [l.get("href") for l in soup.find_all("link", rel=lambda x: x and "canonical" in x)]
                        
                        meta_tags = []
                        for m in soup.find_all("meta"):
                            m_name = (m.get("name") or m.get("property") or "").strip()
                            m_content = (m.get("content") or "").strip()
                            if m_name and m_content:
                                if any(k in m_name.lower() for k in ["desc", "viewport", "og:", "twitter:", "robot", "author", "charset"]):
                                    meta_tags.append(f"{m_name}: {m_content[:150]}")
                        
                        audit_data += f"[PAGE TITLE]: {page_title}\n"
                        audit_data += f"[CANONICAL URL]: {canonicals or 'NONE'}\n"
                        audit_data += f"[META TAGS]:\n" + "\n".join(meta_tags[:15]) + "\n\n"

                        # Extract all links with their attributes (Accessibility + SEO)
                        links = soup.find_all('a', href=True)
                        link_data = " ".join([str(link)[:150] for link in links[:20]])
                        audit_data += f"[LINKS/NAV STRUCTURE]:\n{link_data[:800]}\n\n"

                        # Extract all images with their attributes (Accessibility)
                        images = soup.find_all('img')
                        img_data = " ".join([str(img)[:150] for img in images[:20]])
                        audit_data += f"[IMAGES]:\n{img_data[:600]}\n\n"

                        # Extract all interactive elements (Hydration + Accessibility)
                        interactive = soup.find_all(['button', 'form', 'input', 'select'])
                        interactive_data = " ".join([str(el)[:150] for el in interactive[:15]])
                        audit_data += f"[INTERACTIVE ELEMENTS]:\n{interactive_data[:800]}\n\n"

                        # Extract headings structure (SEO + Accessibility)
                        headings = soup.find_all(['h1', 'h2', 'h3'])
                        heading_data = " ".join([f"<{h.name}>{h.get_text(strip=True)[:80]}</{h.name}>" for h in headings[:15]])
                        audit_data += f"[HEADING STRUCTURE]:\n{heading_data[:500]}\n\n"

                        aggregated_website_data += f"--- PAGE: {current_url} ---\n{audit_data}\n\n"
                        
                        # Extract links for the queue
                        for link in soup.find_all('a', href=True):
                            raw_href = link['href'].split('#')[0]
                            full_link = urljoin(base_domain, raw_href)
                            
                            if is_valid_internal_link(base_domain, full_link) and full_link not in visited_urls and full_link not in queue:
                                queue.append(full_link)
                                
                    except Exception as e:
                        print(f"   ⚠️ Parse error on {current_url}: {e}")
                        
            # Respect target firewalls between batches
            await asyncio.sleep(THROTTLE_SLEEP_SECONDS) 
            print(f"   ({len(visited_urls)}/{max_pages}) Deep Crawl Progress...")
            
    return aggregated_website_data, list(visited_urls)


def process_queue():
    """The Infinite Loop checking Redis for new jobs."""
    while True:
        scan_id = None
        try:
            ticket = REDIS_CLIENT.rpop("scan_queue")
            
            if ticket:
                if isinstance(ticket, str):
                    ticket = json.loads(ticket)
                
                scan_id = ticket['scan_id']
                target_url = ticket['target_url']
                
                print(f"\n🎯 FORENSIC TICKET GRABBED: {scan_id}")
                print(f"🕸️ Deploying Bulletproof Spider to: {target_url}")
                
                if not is_safe_url(target_url):
                    print(f"❌ Security Block: Refusing to crawl internal/invalid URL {target_url}")
                    SUPABASE_CLIENT.table("scans").update({"status": "failed"}).eq("id", scan_id).execute()
                    continue
                
                SUPABASE_CLIENT.table("scans").update({"status": "crawling"}).eq("id", scan_id).execute()

                # --- STEP 1: The Fast Lane (Recursive Crawler) ---
                print("⚡ [FAST LANE] Unleashing the Async Deep Crawler...")
                aggregated_website_data, visited_urls = asyncio.run(async_deep_crawl(target_url, MAX_PAGES_TO_CRAWL))

                # --- STEP 2: The AI Aggregator with Multi-Model Fallback ---
                print(f"🧠 Feeding {len(visited_urls)} pages of aggregated data to Gemini for Granular Auditing...")
                
                # The logic contract for localized remediation and strict scoring
                ai_prompt = f"""
                You are a highly paid, expert Enterprise Web Auditor.
                I have crawled {len(visited_urls)} pages of a website. Below is the aggregated structural and metadata information from the crawled pages.

                AUDIT GUIDELINES:
                1. Identify the top 4 to 8 distinct, most critical vulnerabilities across the website. Group systemic site-wide issues into a single representative vulnerability entry rather than repeating them.
                2. Severity Definitions:
                   - High: Critical functional blockers (broken checkout/forms, keyboard traps, unusable navigation, severe security exposure).
                   - Medium: Significant WCAG standards violations or hydration mismatch risks (missing aria-labels on interactive elements, missing functional alt text, hydration state mismatches).
                   - Low: Minor SEO optimizations or code hygiene (missing optional meta tags, non-ideal heading levels, redundant meta attributes).

                CALCULATE THE GLOBAL SCORE STRICTLY BASED ON THE REPORTED 'critical_vulnerabilities' LIST:
                1. Start at a baseline score of 100.
                2. For each "High" severity vulnerability in your list, subtract 10 points.
                3. For each "Medium" severity vulnerability in your list, subtract 4 points.
                4. For each "Low" severity vulnerability in your list, subtract 1 point.
                5. IMPORTANT: Deduct points ONCE per vulnerability entry in your reported list. Never multiply deductions by the number of crawled pages.
                6. Minimum possible score is 20.
                Example: A report with 0 High, 2 Medium (-6), and 3 Low (-3) MUST receive a score of 91.
                Example: A report with 1 High (-7), 1 Medium (-3), and 2 Low (-2) MUST receive a score of 88.

                Analyze the entire structure and content, and return a strict JSON dictionary matching this exact structure (no markdown wrappers):
                {{
                  "global_score": <calculated integer based strictly on the rubric>,
                  "executive_summary": "<string>",
                  "top_global_issue": "<string>",
                  "critical_vulnerabilities": [
                    {{
                      "id": "vuln-1",
                      "url": "<exact page URL where defect was discovered>",
                      "issue_type": "<Accessibility | Code Error | Hydration | Performance | SEO>",
                      "severity": "<High | Medium | Low>",
                      "file_target": "<suggested file path>",
                      "description": "<precise architectural defect description>",
                      "remediation_code": "<Write the code snippet to fix the issue. Include 2-3 lines of existing surrounding code and use comments like '// ... existing code ...' so the developer knows exactly where to paste this fix, but do NOT write out the entire file.>"
                    }}
                  ]
                }}
                
                Website Aggregated Data:
                {aggregated_website_data[:500000]} 
                """
                
                ai_data = None
                ai_exception = None
                
                # ========================================
                # UNIFIED FALLBACK CHAIN (Gemini + Groq, interleaved in order)
                # Order: gemini-2.5-flash → llama-3.3-70b → gemini-2.5-flash-lite → gemini-3.5-flash → qwen3-32b
                # ========================================
                for provider, model_name in AI_CHAIN:

                    # Skip Groq slots if no key is configured
                    if provider == "groq" and not groq_client:
                        print(f"   ⏭️ Skipping {model_name} — no GROQ_API_KEY set.")
                        continue

                    success = False
                    print(f"🤖 Attempting AI analysis with [{provider.upper()}] model: {model_name}")

                    for attempt in range(AI_MAX_RETRIES):
                        try:
                            if provider == "gemini":
                                ai_response = ai_client.models.generate_content(
                                    model=model_name,
                                    contents=ai_prompt,
                                    config=types.GenerateContentConfig(
                                        response_mime_type="application/json",
                                        temperature=0.0
                                    )
                                )
                                ai_data = json.loads(ai_response.text)

                            elif provider == "groq":
                                # Groq uses a compact prompt — same logic, trimmed context
                                groq_prompt = f"""You are an expert Enterprise Web Auditor. Analyze this website data and return ONLY a JSON object (no markdown, no explanation) matching this schema exactly:
{{"global_score": <integer 20-100>, "executive_summary": "<string>", "top_global_issue": "<string>", "critical_vulnerabilities": [{{"id": "vuln-1", "url": "<url>", "issue_type": "<Accessibility|Code Error|Hydration|Performance|SEO>", "severity": "<High|Medium|Low>", "file_target": "<path>", "description": "<description>", "remediation_code": "<fix snippet>"}}]}}

Scoring: Start at 100. Subtract 7 per High, 3 per Medium, 1 per Low. Min score 20. Report 4-8 distinct issues only.

Website Data:
{aggregated_website_data[:40000]}"""
                                groq_response = groq_client.chat.completions.create(
                                    model=model_name,
                                    messages=[{"role": "user", "content": groq_prompt}],
                                    temperature=0.0,
                                    response_format={"type": "json_object"},
                                )
                                ai_data = json.loads(groq_response.choices[0].message.content)
                                ai_data["ai_provider"] = f"Groq ({model_name})"

                            # Inject scanned URLs into payload for the React UI
                            ai_data["scanned_urls"] = visited_urls
                            success = True
                            break  # Success — stop retrying this model

                        except Exception as ai_error:
                            error_str = str(ai_error).upper()
                            retryable = any(err in error_str for err in [
                                "503", "429", "UNAVAILABLE", "RESOURCE_EXHAUSTED",
                                "10053", "CONNECTION", "RATE_LIMIT", "OVERLOADED"
                            ])
                            if retryable and attempt < AI_MAX_RETRIES - 1:
                                sleep_time = 10 * (2 ** attempt)
                                print(f"   ⚠️ [{provider.upper()}] busy/connection issue. Retrying in {sleep_time}s... (Attempt {attempt + 2}/{AI_MAX_RETRIES})")
                                time.sleep(sleep_time)
                            else:
                                ai_exception = ai_error
                                break  # Non-retryable — move to next model in chain

                    if success:
                        print(f"✅ [{provider.upper()}] {model_name} succeeded!")
                        break  # Got data — stop the chain
                    else:
                        print(f"   ⚠️ [{provider.upper()}] {model_name} failed. Trying next in chain...")

                if not ai_data:
                    if ai_exception:
                        raise ai_exception
                    else:
                        raise Exception("All AI providers (Gemini + Groq) failed. Check API keys and quotas.")

                print(f"✅ AI Global Score: {ai_data.get('global_score')}/100")
                print(f"✅ Issue Found: {ai_data.get('top_global_issue')}")

                # --- STEP 3: Browser Engine (Core Web Vitals & Issue Screenshots) ---
                print("⚡ [BROWSER ENGINE] Launching Playwright for Core Web Vitals & Forensic Visuals...")
                critical_vulns = ai_data.get("critical_vulnerabilities", [])
                screenshot_cache = {}  # Cache to avoid screenshotting the same URL twice

                try:
                    with sync_playwright() as p:
                        browser = p.chromium.launch(headless=True)
                        page = browser.new_page()

                        # 1. Real Core Web Vitals Extraction on Target URL
                        print(f"   ⏱️ Measuring Real Core Web Vitals for: {target_url}...")
                        try:
                            page.goto(target_url, wait_until="load", timeout=45000)
                            perf_metrics = page.evaluate('''() => {
                                const nav = performance.getEntriesByType('navigation')[0] || {};
                                const paintEntries = performance.getEntriesByType('paint') || [];
                                const fcpEntry = paintEntries.find(e => e.name === 'first-contentful-paint');
                                const resources = performance.getEntriesByType('resource') || [];
                                const totalBytes = resources.reduce((acc, r) => acc + (r.transferSize || 0), nav.transferSize || 0);

                                const loadTime = Math.round(nav.loadEventEnd || nav.duration || 0);
                                const fcp = fcpEntry ? Math.round(fcpEntry.startTime) : null;
                                const dcl = Math.round(nav.domContentLoadedEventEnd || 0);
                                const ttfb = Math.round(nav.responseStart - nav.requestStart || 0);

                                return {
                                    load_time_ms: loadTime,
                                    fcp_ms: fcp,
                                    dom_content_loaded_ms: dcl,
                                    ttfb_ms: ttfb,
                                    total_requests: resources.length + 1,
                                    transfer_size_kb: Math.round(totalBytes / 1024),
                                    speed_rating: loadTime < 2000 ? "Fast" : loadTime < 4000 ? "Average" : "Slow"
                                };
                            }''')
                            ai_data["performance_metrics"] = perf_metrics
                            print(f"   ⚡ Speed: {perf_metrics.get('load_time_ms')}ms | FCP: {perf_metrics.get('fcp_ms')}ms | Rating: {perf_metrics.get('speed_rating')}")
                        except Exception as perf_err:
                            print(f"   ⚠️ Could not measure Web Vitals: {perf_err}")

                        # 2. Issue-Specific Screenshots for Vulnerabilities
                        for index, vuln in enumerate(critical_vulns):
                            vuln_url = vuln.get("url")
                            if not vuln_url:
                                continue

                            # Skip duplicate URLs by reusing cached screenshot URL
                            if vuln_url in screenshot_cache:
                                vuln["screenshot_url"] = screenshot_cache[vuln_url]
                                continue

                            print(f"   📸 Screenshotting vulnerability at: {vuln_url}")
                            screenshot_filename = f"vuln_{scan_id}_{index}.png"

                            try:
                                page.goto(vuln_url, wait_until="domcontentloaded", timeout=45000)
                                page.wait_for_timeout(2500)
                                page.screenshot(path=screenshot_filename, full_page=False)

                                # Upload to Supabase Storage with upsert to avoid conflicts
                                with open(screenshot_filename, "rb") as f:
                                    SUPABASE_CLIENT.storage.from_("screenshots").upload(
                                        screenshot_filename,
                                        f,
                                        file_options={"x-upsert": "true"}
                                    )

                                public_url = SUPABASE_CLIENT.storage.from_("screenshots").get_public_url(screenshot_filename)
                                vuln["screenshot_url"] = public_url
                                screenshot_cache[vuln_url] = public_url

                            except Exception as e:
                                print(f"   ⚠️ Screenshot failed for {vuln_url}: {e}")
                            finally:
                                # Clean up local image
                                if os.path.exists(screenshot_filename):
                                    os.remove(screenshot_filename)

                        browser.close()
                except Exception as e:
                    print(f"   ⚠️ Playwright initialization failed: {e}")

                # --- STEP 4: Mission Complete ---
                print("💾 Saving massive AI audit to The Vault...")
                SUPABASE_CLIENT.table("audit_results").insert({
                    "scan_id": scan_id,
                    "category": "ai_audit_deep_crawl",
                    "raw_data": ai_data
                }).execute()
                
                now_iso = datetime.now(timezone.utc).isoformat()
                SUPABASE_CLIENT.table("scans").update({
                    "status": "completed",
                    "completed_at": now_iso
                }).eq("id", scan_id).execute()
                print("🎉 Spider mission accomplished! Waiting for next job...")
                
            else:
                time.sleep(2)
                
        except Exception as e:
            print(f"❌ Worker hit a critical error: {e}")
            try:
                if scan_id:
                    now_iso = datetime.now(timezone.utc).isoformat()
                    SUPABASE_CLIENT.table("scans").update({
                        "status": "failed",
                        "completed_at": now_iso
                    }).eq("id", scan_id).execute()
            except Exception:
                pass
            time.sleep(5)

if __name__ == "__main__":
    process_queue()