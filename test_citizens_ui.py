import app

client = app.app.test_client()

def test_citizen(email, password, expect_linked, last4=None, cases=0):
    print(f"\n--- Testing {email} ---")
    with client.session_transaction() as sess:
        sess.clear()
        
    resp = client.post('/login', data={'email': email, 'password': password}, follow_redirects=True)
    html = resp.data.decode()
    
    if expect_linked:
        assert 'XXXX-XXXX-' + last4 in html or 'Identity Linked' in html or 'Update Aadhaar' in html, "Should show linked state"
        print("  Linked state verified in UI.")
    else:
        assert 'No Aadhaar linked' in html or 'Verify Citizen Identity' in html or 'Link Aadhaar' in html, "Should show unlinked state"
        print("  Unlinked state verified in UI.")
        
    # Test Check Case Status API
    if expect_linked:
        resp = client.post('/api/citizen/case-status', data={'aadhaar': '111111111111' if last4=='1111' else ('222222222222' if last4=='2222' else '333333333333')})
        res = resp.get_json()
        if cases > 0:
            assert len(res.get('records', [])) == cases, f"Expected {cases} cases, got {len(res.get('records', []))}"
            print(f"  Cases verified: {cases} found.")
        else:
            assert len(res.get('records', [])) == 0, "Expected 0 cases"
            print("  Cases verified: 0 found.")

test_citizen('testcitizen1@example.test', 'password123', True, '1111', 2)
test_citizen('testcitizen2@example.test', 'password123', True, '2222', 1)
test_citizen('testcitizen3@example.test', 'password123', True, '3333', 0)
test_citizen('testcitizen4@example.test', 'password123', False)
print("All tests passed!")
