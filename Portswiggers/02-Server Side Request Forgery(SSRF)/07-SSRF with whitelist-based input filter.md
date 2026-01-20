## 🎯 Objective

Exploit a **Server-Side Request Forgery (SSRF)** vulnerability protected by a **whitelist-based input filter** by abusing **URL parsing inconsistencies**, allowing access to an **internal admin interface** and deletion of the user **`carlos`**.

---

## 🧩 1. Vulnerability Discovery

### Feature Tested

- **Check stock** functionality on the product page

This feature sends a **POST request** to the backend containing a URL parameter.

### Parameter Identified

- **`stockApi`**

The backend server fetches the supplied URL to retrieve stock information.

---

## 🔎 2. Whitelist-Based Input Filter Identified

### Allowed Domain

The application only allowed URLs containing the domain:

```
stock.weliketoshop.net
```

### Blocked Attempts

When attempting values such as:

- `localhost`
- Internal IP addresses

The application responded with:

- **500 Internal Server Error**

This indicates a **strict whitelist**, implemented using **string matching**, not proper URL parsing.

---

## 🧠 3. Why This Whitelist Is Weak

The filter only checks whether the allowed domain **appears in the URL string**, not whether it is actually the **destination host**.

This makes it vulnerable to:

- Userinfo (`@`) abuse
- Fragment (`#`) parsing tricks
- Encoding confusion

---

## 🔓 4. Whitelist Bypass Technique

### Techniques Used

- **Userinfo (`@`) abuse**
- **Fragment identifier (`#`)**
- **Double URL encoding**

### Why This Works

- Everything **before `@`** is treated as userinfo
- Everything **after `@`** becomes the actual host
- The fragment (`#`) is ignored by the server when making requests
- Double encoding prevents the filter from recognizing blocked characters

---

## 🔗 5. Final Exploit Payload

The following value was supplied to the `stockApi` parameter:

```
http%3a%2f%2flocalhost%2523%40stock.weliketoshop.net/admin/delete?username=carlos
```

### Decoded Interpretation

```
http://localhost#@stock.weliketoshop.net/admin/delete?username=carlos

```

- The filter sees: `stock.weliketoshop.net` ✅
- The backend resolves the request to: `localhost` ❌
- The fragment hides the true destination from the filter

---

## 🧨 6. Privileged Action Execution

The backend request reached the internal admin interface and executed:

```
/admin/delete?username=carlos
```

### Result

- User **`carlos`** successfully deleted
- The lab was immediately marked as **solved**

---

## 📊 7. Final Result

```
Vulnerabilitytype: SSRF
Filtertype: Whitelist (string matching)
Bypass technique: @ + # +double URLencoding
Impact:Internaladminaccess
Lab status: Solved

```

---

## 🔮 8. Key Takeaways (Attacker Mindset)

- Whitelists are useless if they rely on **string matching**
- URL parsing is complex — attackers exploit that complexity
- The `@` symbol is one of the most reliable SSRF bypass primitives
- Encoding layers often defeat “secure” filters
- If a backend fetches URLs, **assume SSRF until proven otherwise**

---

## 🧭 9. Notes for My Future Self

- Always test `@`, `#`, and encoding combinations against whitelists
- Never trust filters that don’t parse URLs properly
- SSRF defenses must validate:
    - Scheme
    - Host
    - Port
    - Redirect behavior
- Anything less is bypassable
