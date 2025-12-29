## 🎯 Objective

Exploit a **Server-Side Request Forgery (SSRF)** vulnerability to access an **internal back-end system hosted on a private IP address**, then perform an **unauthorized administrative action**.

---

## 🧩 1. Initial Recon & Functionality Analysis

### Application Context

The application is an **e-commerce platform** that allows users to browse products and check stock availability before purchasing.

### Stock Check Functionality

Each product includes a **“Check stock”** button that triggers a backend request to a stock-checking service.

This functionality is a common SSRF target because:

- The server fetches a URL on behalf of the user
- The destination is controlled via user input

---

## 🔍 2. Identifying the SSRF Injection Point

### Vulnerable Parameter

- **Parameter:** `stockApi`
- **Location:** HTTP POST body
- **Triggered by:** Clicking “Check stock”

### Normal Parameter Value

```
http://stock.weliketoshop.net:8080/product/stock/check?productId=1&storeId=1

```

### Key Observation

- The parameter contains a **full URL**
- This confirms the backend server makes an HTTP request to the supplied address
- No validation restricts access to internal destinations

This confirms `stockApi` as an **SSRF sink**.

---

## 🧠 3. Why Localhost Was Not Enough

Unlike the previous lab:

- Accessing `localhost` did **not** expose the admin interface
- This indicates the admin panel is hosted on a **different internal system**, not the same server

This shifts the attacker mindset from:

> “Attack the same server”
> 

to:

> “Enumerate the internal network”
> 

---

## 🧪 4. Internal Network Enumeration via SSRF

### Strategy

Use SSRF to:

- Target **private IP ranges**
- Identify reachable internal services
- Discover administrative interfaces

### Private IP Range Tested

```
192.168.0.1-255

```

### Discovered Internal System and deleted carlos user

```
http://192.168.0.160:8080/admin/delete?username=carlos

```

### Result

- The admin interface was accessible
- No authentication was required
- Confirms successful **cross-system SSRF**
- <img width="1188" height="199" alt="image" src="https://github.com/user-attachments/assets/e3c748f8-475a-4d75-8d3b-167ee0e1849b" />


---

## 🚨 5. Exploiting the Internal Admin Interface

### Discovered Endpoint

The internal admin panel exposed a user management function.

### Exploit Request

```
http://192.168.0.160:8080/admin/delete?username=carlos

```

### Result

- The user **carlos** was deleted successfully
- The request executed with **internal system privileges**
- No authentication or authorization checks were enforced

---

## 📊 6. Final Result

- SSRF used to access a **different back-end system**
- Internal admin panel discovered via IP enumeration
- Administrative action performed successfully
- Lab marked as **Solved**

---

## 🔮 7. Key Takeaways

### SSRF Testing Mindset

- SSRF is not limited to `localhost`
- Always enumerate:
    - Private IP ranges
    - Different ports
    - Adjacent internal systems
- SSRF often acts as a **bridge between network segments**

### Why This Lab Matters

- Demonstrates lateral movement via SSRF
- Shows how one vulnerable feature can expose an entire internal network
- Highlights the danger of trusting backend-to-backend traffic

---

## 🧭 8. Notes for My Future Self

- Stock-check APIs are prime SSRF targets
- If localhost fails, enumerate internal IPs
- Admin panels are often hosted on separate systems
- SSRF impact depends on **what the server can reach**
- Network isolation alone is not a defense
