"""
QR Code Generator for Testing Secure QR Analyzer
Generates test QR codes with different risk levels
"""

import qrcode
from PIL import Image, ImageDraw, ImageFont
import os

# Create test directory
os.makedirs("test_qrcodes", exist_ok=True)

# Test URLs with expected risk levels
test_urls = [
    # SAFE URLs (should score < 25)
    ("SAFE_google.png", "https://www.google.com", "SAFE", "Legitimate search engine"),
    ("SAFE_github.png", "https://github.com", "SAFE", "Legitimate development platform"),
    ("SAFE_stackoverflow.png", "https://stackoverflow.com", "SAFE", "Legitimate Q&A site"),
    
    # SUSPICIOUS URLs (should score 25-55)
    ("SUSPICIOUS_shortened.png", "https://bit.ly/3f7K2pL", "SUSPICIOUS", "URL shortener"),
    ("SUSPICIOUS_login.png", "http://login-verify-account.com", "SUSPICIOUS", "Suspicious keywords"),
    ("SUSPICIOUS_http.png", "http://example.com/login", "SUSPICIOUS", "No HTTPS"),
    
    # DANGEROUS URLs (should score 55-80)
    ("DANGEROUS_ip.png", "http://192.168.1.1/banking/login", "DANGEROUS", "IP address + banking"),
    ("DANGEROUS_phishing.png", "http://paypal-verify.secure-login.tk", "DANGEROUS", "Phishing pattern"),
    ("DANGEROUS_malicious.png", "http://185.130.5.253/secure/account", "DANGEROUS", "IP + secure keywords"),
    
    # CRITICAL URLs (should score > 80)
    ("CRITICAL_mixed.png", "http://185.130.5.253/login/verify/account/banking", "CRITICAL", "Multiple threat indicators"),
]

def generate_qr_codes():
    """Generate QR codes for all test URLs"""
    
    print("🔐 Generating Test QR Codes for Security Scanner")
    print("="*50)
    
    for filename, url, risk_level, description in test_urls:
        try:
            # Create QR code
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_M,
                box_size=10,
                border=4,
            )
            qr.add_data(url)
            qr.make(fit=True)
            
            # Generate QR image
            qr_img = qr.make_image(fill_color="black", back_color="white")
            
            # Convert to RGB if needed
            if qr_img.mode != 'RGB':
                qr_img = qr_img.convert('RGB')
            
            # Create label area
            label_height = 80
            total_height = qr_img.size[1] + label_height
            
            # Create new image with white background
            img_with_label = Image.new('RGB', (qr_img.size[0], total_height), 'white')
            
            # Paste QR code at the top
            img_with_label.paste(qr_img, (0, 0))
            
            # Draw labels
            draw = ImageDraw.Draw(img_with_label)
            
            # Try to use a default font, fall back to default if not available
            try:
                # Try to get a system font
                font_title = ImageFont.truetype("arial.ttf", 16)
                font_desc = ImageFont.truetype("arial.ttf", 12)
            except:
                # Use default font if arial not available
                font_title = ImageFont.load_default()
                font_desc = ImageFont.load_default()
            
            # Set colors based on risk level
            if risk_level == "SAFE":
                color = (16, 185, 129)  # Green
            elif risk_level == "SUSPICIOUS":
                color = (245, 158, 11)  # Orange
            elif risk_level == "DANGEROUS":
                color = (239, 68, 68)   # Red
            else:  # CRITICAL
                color = (127, 29, 29)   # Dark red
            
            # Draw risk level text
            draw.text((10, qr_img.size[1] + 5), 
                     f"[{risk_level}] {url}", 
                     fill=color, font=font_title)
            
            # Draw description
            draw.text((10, qr_img.size[1] + 30), 
                     f"Expected: {risk_level} - {description}", 
                     fill=(100, 100, 100), font=font_desc)
            
            # Draw instruction
            draw.text((10, qr_img.size[1] + 55), 
                     "Hold this QR code up to your camera for testing", 
                     fill=(150, 150, 150), font=font_desc)
            
            # Save the image
            filepath = os.path.join("test_qrcodes", filename)
            img_with_label.save(filepath)
            
            print(f"✅ Generated: {filename}")
            print(f"   URL: {url}")
            print(f"   Expected: {risk_level} - {description}")
            print()
            
        except Exception as e:
            print(f"❌ Error generating {filename}: {e}")

def generate_batch_for_printing():
    """Generate a single sheet with multiple QR codes for printing"""
    
    print("\n📄 Generating batch sheet for printing...")
    
    # Create a grid of QR codes
    cols = 3
    rows = 3
    qr_size = 200
    padding = 20
    
    sheet_width = cols * (qr_size + padding) + padding
    sheet_height = rows * (qr_size + padding) + padding + 100
    
    # Create blank sheet
    sheet = Image.new('RGB', (sheet_width, sheet_height), 'white')
    draw = ImageDraw.Draw(sheet)
    
    # Add title
    try:
        font_title = ImageFont.truetype("arial.ttf", 24)
    except:
        font_title = ImageFont.load_default()
    
    draw.text((sheet_width//2 - 150, 10), "QR Security Scanner Test Sheet", 
              fill=(0, 0, 0), font=font_title)
    
    # Generate and place QR codes
    for idx, (filename, url, risk_level, description) in enumerate(test_urls[:9]):  # Max 9 QR codes
        row = idx // cols
        col = idx % cols
        
        # Calculate position
        x = padding + col * (qr_size + padding)
        y = padding + 60 + row * (qr_size + padding)
        
        # Generate QR
        qr = qrcode.QRCode(box_size=5, border=2)
        qr.add_data(url)
        qr.make()
        qr_img = qr.make_image(fill_color="black", back_color="white").resize((qr_size, qr_size))
        
        # Convert to RGB if needed
        if qr_img.mode != 'RGB':
            qr_img = qr_img.convert('RGB')
        
        # Paste onto sheet
        sheet.paste(qr_img, (x, y))
        
        # Add label
        label_y = y + qr_size + 5
        
        # Set color based on risk
        if risk_level == "SAFE":
            color = (16, 185, 129)
        elif risk_level == "SUSPICIOUS":
            color = (245, 158, 11)
        elif risk_level == "DANGEROUS":
            color = (239, 68, 68)
        else:
            color = (127, 29, 29)
        
        try:
            font_label = ImageFont.truetype("arial.ttf", 10)
        except:
            font_label = ImageFont.load_default()
        
        draw.text((x + 5, label_y), risk_level, fill=color, font=font_label)
        draw.text((x + 5, label_y + 15), url[:25] + "...", fill=(100, 100, 100), font=font_label)
    
    # Save batch sheet
    sheet_path = os.path.join("test_qrcodes", "batch_sheet.png")
    sheet.save(sheet_path)
    print(f"✅ Generated batch sheet: {sheet_path}")

def create_simple_qr(url, filename, risk_level=None):
    """Create a simple QR code without labels (for mobile display)"""
    qr = qrcode.QRCode(box_size=8, border=2)
    qr.add_data(url)
    qr.make()
    img = qr.make_image(fill_color="black", back_color="white")
    
    filepath = os.path.join("test_qrcodes", filename)
    img.save(filepath)
    print(f"✅ Created simple QR: {filename}")

if __name__ == "__main__":
    print("="*60)
    print("QR CODE GENERATOR FOR SECURITY SCANNER TESTING")
    print("="*60)
    print()
    
    # Generate individual QR codes with labels
    generate_qr_codes()
    
    # Generate a batch sheet for printing
    generate_batch_for_printing()
    
    # Create simple versions for mobile viewing
    print("\n📱 Creating simple QR codes for mobile...")
    simple_urls = [
        ("https://www.google.com", "simple_google.png", "SAFE"),
        ("http://login-verify.com", "simple_phishing.png", "SUSPICIOUS"),
        ("http://192.168.1.1/banking", "simple_malicious.png", "DANGEROUS"),
    ]
    
    for url, filename, risk in simple_urls:
        create_simple_qr(url, filename, risk)
    
    print("\n" + "="*60)
    print("✅ ALL QR CODES GENERATED SUCCESSFULLY!")
    print("="*60)
    print("\n📁 Files saved in 'test_qrcodes' folder")
    print("\nInstructions:")
    print("1. Open the 'test_qrcodes' folder")
    print("2. Display any QR code to your camera")
    print("3. The scanner should analyze and show the risk level")
    print("4. SAFE URLs should show green, DANGEROUS should show red")
    print("\n🎯 Expected Results:")
    print("   - Google/GitHub -> SAFE (<25 score)")
    print("   - bit.ly/login-verify -> SUSPICIOUS (25-55 score)")
    print("   - IP addresses/banking -> DANGEROUS (55-80 score)")
    print("   - Mixed indicators -> CRITICAL (>80 score)")