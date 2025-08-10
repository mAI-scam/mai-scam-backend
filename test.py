import os
import json
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

SEA_LION_API_KEY = os.getenv("SEA_LION_API_KEY")

client = OpenAI(
    api_key=SEA_LION_API_KEY,
    base_url="https://api.sea-lion.ai/v1"
)

# List of messages to check for spam (Chinese, Singlish, and Bahasa Melayu examples)
messages_to_check = [
    # Chinese (Phishing with suspicious URL)
    "您的Shopee账户即将过期！请立即点击链接更新信息：https://www.shoppe5.123.com.vercel.my/login 避免账户被冻结。",  # phishing
    # Chinese (Phishing with fake bank URL)
    "恭喜你中奖了！点击这个链接领取你的奖金：https://maybank-malaysia.secure-login.net.my",  # phishing
    # Chinese (Non-spam)
    "您的快递已到，请到前台领取。",  # non-spam

    # Singlish (Phishing with suspicious Shopee URL)
    "Eh bro, your Shopee account got problem leh! Click here to verify fast fast: www.shoppe-security.verify123.com.my or else account will be suspended!",  # phishing
    # Singlish (Phishing with fake banking)
    "Wah! You strike lottery already! Click this link to claim RM10,000: https://dbs-bank.winner-claim.sg.net",  # phishing
    # Singlish (Non-spam)
    "Eh, later we makan at hawker centre or not?",  # non-spam

    # Bahasa Melayu (Phishing with fake e-wallet)
    "Tahniah! Anda menang RM5,000 dari Touch 'n Go eWallet. Sila klik pautan ini untuk tuntut: https://touchngo-ewallet.claim-rewards.my.net",  # phishing
    # Bahasa Melayu (Phishing with fake Grab URL)
    "Akaun Grab anda akan ditutup dalam 24 jam. Kemas kini maklumat di: https://grab-malaysia.account-verify.com.sg/update",  # phishing
    # Bahasa Melayu (Non-spam)
    "Sila hadir ke mesyuarat pada pukul 10 pagi esok di bilik mesyuarat utama.",  # non-spam

    # English (Phishing with fake government URL)
    "URGENT: Your MySejahtera account requires verification. Click here immediately: https://mysejahtera-gov.verification.my.com or face penalties.",  # phishing
]

for idx, message_to_check in enumerate(messages_to_check, 1):
    completion = client.chat.completions.create(
        model="aisingapore/Llama-SEA-LION-v3.5-8B-R",
        messages=[
            {
                "role": "user",
                "content": f"Analyze this message for scams. Respond ONLY in valid JSON format with two fields: 'classification' (either 'spam' or 'not spam') and 'warning_signs' (short, simple explanation in the same language as the message about what makes this suspicious or safe).\n\nMessage: {message_to_check}\n\nResponse format:\n{{\n  \"classification\": \"spam\" or \"not spam\",\n  \"warning_signs\": \"explanation in local language\"\n}}"
            }
        ],
        extra_body={
            "chat_template_kwargs": {
                "thinking_mode": "on"
            }, 
            "cache": {
                "no-cache": True
            }
        },
    )
    
    try:
        # Parse the JSON response
        response_content = completion.choices[0].message.content.strip()
        # Remove any markdown formatting if present
        if response_content.startswith("```json"):
            response_content = response_content.replace("```json", "").replace("```", "").strip()
        
        result = json.loads(response_content)
        
        print(f"Message {idx}: {message_to_check}")
        print(f"Result: {json.dumps(result, ensure_ascii=False, indent=2)}\n")
        
    except json.JSONDecodeError:
        print(f"Message {idx}: {message_to_check}")
        print(f"Error: Could not parse JSON response")
        print(f"Raw response: {completion.choices[0].message.content}\n")