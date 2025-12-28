## 🎯 Objective

Exploit a **Server-Side Request Forgery (SSRF)** vulnerability to access an **internal admin interface** running on the local server and perform an **unauthorized administrative action**.

---

## 🧩 1. Initial Recon & Functionality Analysis

### Application Context

The lab simulates an **e-commerce website** where users can browse products and check their availability before purchasing.

### Stock Check Functionality

Each product includes a **“Check stock”** button.

Clicking this button triggers a backend request to an internal stock-checking service.

This functionality immediately stands out as a potential SSRF vector because:

- The server fetches a URL on behalf of the user
- The destination appears to be configurable via user-controlled input

---

## 🔍 2. Identifying the SSRF Injection Point

### Vulnerable Parameter

- **Parameter:** `stockApi`
- **Location:** HTTP POST body
- **Request Type:** Sent when checking product stock

### Normal Parameter Value

```markdown
http://stock.weliketoshop.net:8080/product/stock/check?productId=1&storeId=1
```

### Key Observation

- The parameter contains a **full URL**
- This indicates the backend server makes an **HTTP request to the supplied address**
- No validation appears to restrict internal destinations

This confirms `stockApi` as a **classic SSRF sink**.

---

## 🧪 3. Confirming SSRF by Targeting Localhost

### Test Payload

The hostname in the `stockApi` parameter was modified to point to the local server:

```
http://localhost
```

### Result

- The response returned an **internal admin panel**
- This confirms:
    - The backend server is issuing the request
    - Requests to `localhost` are allowed
    - Internal services are exposed through SSRF

At this point, SSRF is **fully confirmed**.

---

## 🧠 4. Understanding the Impact

### Why This Works

- The application trusts user-supplied URLs
- The backend server has access to internal services
- `localhost` resolves to the server itself
- No allowlist or hostname validation is enforced

This allows an attacker to:

- Access internal admin interfaces
- Interact with privileged endpoints
- Perform sensitive actions

---

## 🚨 5. Exploiting the Admin Interface

### Discovered Admin Endpoint

The internal admin panel exposed a user management endpoint.

### Exploit Request

```
http://localhost/admin/delete?username=carlos
```

### Result

- The user **carlos** was deleted successfully
- No authentication was required
- Action executed with **server-level privileges**

---

## 📊 6. Final Result

- Internal admin interface accessed via SSRF
- Administrative action performed successfully
- Target user deleted
- Lab marked as **Solved**
- Screenshot:
-   <img width="1173" height="191" alt="image" src="https://github.com/user-attachments/assets/8d1a1823-ad01-47f9-b3da-ce64688ccbc5" />


---

## 🔮 7. Key Takeaways

### SSRF Testing Mindset

- Any feature that fetches a URL is a potential SSRF
- Always test:
    - `localhost`
    - `127.0.0.1`
    - Internal hostnames
    - Different ports
- SSRF often leads to:
    - Admin panels
    - Metadata services
    - Internal APIs

### Why SSRF Is Dangerous

- Bypasses network segmentation
- Turns the server into an internal proxy
- Often leads directly to **full compromise**

---

## 🧭 8. Notes for My Future Self

- Stock checkers are SSRF magnets
- Full URLs in parameters are a red flag
- Always try `localhost` first
- SSRF impact depends on **what the server can reach**
- Internal admin panels are common and often unprotected
