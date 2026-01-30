# test_user_management.py
import os
import sys
import importlib.util

print("="*70)
print("USER MANAGEMENT & ROLES - COMPREHENSIVE TEST")
print("="*70)

# Test 1: Check if all required files exist
print("\n📁 TEST 1: Checking required files...")
required_files = [
    "app.py",
    "templates/login.html",
    "templates/profile.html",
    "templates/edit_profile.html",
    "templates/edit_password.html",
    "templates/forgot_password.html",
    "templates/reset_password.html",
    "templates/user_security.html",
    "templates/users.html"
]

all_files_exist = True
for file in required_files:
    if os.path.exists(file):
        print(f"  ✅ {file}")
    else:
        print(f"  ❌ {file} - MISSING")
        all_files_exist = False

# Test 2: Check app.py structure
print("\n🔍 TEST 2: Checking app.py structure...")
try:
    with open("app.py", "r", encoding="utf-8") as f:
        content = f.read()
    
    required_routes = [
        "@app.route('/login'",
        "@app.route('/logout'",
        "@app.route('/profile'",
        "@app.route('/profile/edit'",
        "@app.route('/profile/password'",
        "@app.route('/forgot_password'",
        "@app.route('/reset_password/'",
        "@app.route('/users'",
        "@app.route('/admin/user_security/'"
    ]
    
    missing_routes = []
    for route in required_routes:
        if route in content:
            print(f"  ✅ {route}...")
        else:
            print(f"  ❌ {route}... - NOT FOUND")
            missing_routes.append(route)
    
    # Check for User model fields
    user_fields = [
        "reset_token",
        "reset_token_expiry", 
        "failed_login_attempts",
        "account_locked_until",
        "last_login",
        "created_at"
    ]
    
    print("\n  Checking User model fields...")
    for field in user_fields:
        if field in content:
            print(f"    ✅ {field}")
        else:
            print(f"    ❌ {field} - NOT FOUND")
            
except Exception as e:
    print(f"  ❌ Error reading app.py: {e}")

# Test 3: Check database
print("\n💾 TEST 3: Checking database...")
if os.path.exists("documents.db"):
    print("  ✅ documents.db exists")
    db_size = os.path.getsize("documents.db")
    print(f"  📊 Database size: {db_size:,} bytes")
else:
    print("  ⚠️  documents.db not found (will be created when app starts)")

# Test 4: Summary
print("\n" + "="*70)
print("📊 TEST SUMMARY")
print("="*70)

if all_files_exist and len(missing_routes) == 0:
    print("✅ All critical files and routes are present!")
    print("\n🎯 NEXT STEPS - MANUAL TESTS:")
    print("1. Start Flask app: python app.py")
    print("2. Open browser to: http://127.0.0.1:5000")
    print("3. Test login with: admin / admin123")
    print("4. Test forgot password flow")
    print("5. Test account lockout (5 wrong passwords)")
    print("6. Test admin user management")
    print("\n🚀 If all manual tests work, User Management is COMPLETE!")
else:
    print("⚠️  Some issues found:")
    if not all_files_exist:
        print("  • Missing template files")
    if missing_routes:
        print(f"  • Missing routes in app.py: {len(missing_routes)}")
    print("\n🔧 Fix the issues above before proceeding.")

print("\n" + "="*70)
print("QUICK START COMMANDS:")
print("="*70)
print("1. To start the app:")
print("   python app.py")
print("\n2. If you get database errors, delete and recreate:")
print("   del documents.db")
print("   python app.py")
print("\n3. To test login directly:")
print("   Open: http://127.0.0.1:5000/login")
print("\nPress Ctrl+C to stop the Flask app")
print("="*70)