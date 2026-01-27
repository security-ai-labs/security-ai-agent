# This file contains intentionally vulnerable code for testing the security analyzer
# DO NOT use this code in production!

def vulnerable_query(user_id):
    """SQL Injection vulnerability - user input directly concatenated to query"""
    query = "SELECT * FROM users WHERE id = " + str(user_id)
    return execute(query)

def vulnerable_xss(user_input):
    """XSS vulnerability - direct innerHTML usage"""
    html = "<div>" + user_input + "</div>"
    document.innerHTML = html
    return html

def vulnerable_reentrancy(amount):
    """Reentrancy vulnerability in smart contract"""
    msg.sender.call{value: amount}("")
    balance[msg.sender] -= amount

def vulnerable_unchecked_call():
    """Unchecked low-level call"""
    address(recipient).call(abi.encodeWithSignature("receive()"))
    balances[msg.sender] = 0

def safe_query(user_id):
    """Safe version using parameterized query"""
    query = "SELECT * FROM users WHERE id = ?"
    return execute(query, (user_id,))

def safe_reentrancy(amount):
    """Safe version using checks-effects-interactions pattern"""
    require(balance[msg.sender] >= amount)
    balance[msg.sender] -= amount
    msg.sender.call{value: amount}("")