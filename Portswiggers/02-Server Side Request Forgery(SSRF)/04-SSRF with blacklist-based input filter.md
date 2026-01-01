## 🎯 Objective

Exploit a **Server-Side Request Forgery (SSRF)** vulnerability protected by a **blacklist-based input filter** to access an internal admin interface and **delete the user `carlos`**.

---

## 🧩 1. Vulnerability Discovery

### Entry Point Identification

While interacting with the product stock functionality, a **POST request** was observed being sent to the backend when clicking **“Check stock”**.

Inside the POST body, a parameter named **`stockApi`** was found to contain a URL.

### Normal Behavior

```
stockApi=http://stock.weliketoshop.net:8080/product/stock/check?productId=1&storeId=1
```

This strongly indicates:

- The backend server fetches the URL server-side
- The application trusts user-controlled input for backend requests

This is a **classic SSRF attack surface**.

---

## 🧠 2. Blacklist-Based Filtering Observed

Initial SSRF attempts using common internal targets were blocked.

### Blocked Patterns

The application rejected requests containing:

- `localhost`
- `127.0.0.1`
- `/admin`

Whenever these appeared, the application blocked the request instead of forwarding it.

This confirms the presence of a **blacklist-based input filter**, rather than a proper allowlist or URL parsing validation.

---

## 🔓 3. Bypassing the Blacklist

### 1️⃣ Bypassing Localhost Restrictions

Instead of using `127.0.0.1`, the loopback address was rewritten as:

```
127.1

```

This works because:

- `127.0.0.0/8` is all loopback
- Many filters only block the exact string `127.0.0.1`
- The backend OS still resolves `127.1` to localhost

---

### 2️⃣ Bypassing `/admin` Filtering with Double URL Encoding

The `/admin` path was blocked when sent directly.

To bypass this:

- Each character in `admin` was **double URL‑encoded**
- This bypasses string-based filters that do not decode input multiple times
- The backend decodes it later, after the filter is bypassed

Encoded form:

```
%25%36%31%25%36%34%25%36%44%25%36%39%25%36%45

```

Which resolves to:

```
/admin

```

---

## ✅ 4. Final Exploit Payload

The final working payload used in the `stockApi` parameter was:

```
http%3a%2f%2f127.1%2f%25%36%31%25%36%34%25%36%44%25%36%39%25%36%45/delete?username=carlos

```

### What This Does

- Forces the backend to make a request to:
    - Internal host: `127.1`
    - Internal path: `/admin/delete`
- Deletes the user `carlos` from the admin interface

---

## 🏁 5. Lab Completion

- The request was processed successfully
- The user `carlos` was deleted
- The lab was immediately marked as **solved**

---

## 🔎 6. Key Takeaways

### Why Blacklists Fail

- Blacklists only block **known strings**
- They do not understand:
    - IP ranges
    - URL normalization
    - Encoding layers
- Attackers only need **one alternative representation**

### Attacker Mindset

- SSRF is about **how the backend parses URLs**, not what the frontend allows
- If input reaches a request function:
    - Assume filters are weak
    - Try alternate IP formats
    - Try encoding, double encoding, mixed encoding
- Never trust a filter that works by “blocking words”

---

## 🧭 7. Notes for Future Testing

- Always test SSRF inputs with:
    - Alternate loopback IPs (`127.1`, `2130706433`, IPv6)
    - Encoded paths
    - Double and mixed encoding
- Blacklist = bypass opportunity
- Proper SSRF defense requires **strict allowlists**, not string matching
