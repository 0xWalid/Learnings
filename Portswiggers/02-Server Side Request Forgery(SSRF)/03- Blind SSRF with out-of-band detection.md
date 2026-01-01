## 🎯 Objective

Identify and confirm a **blind Server-Side Request Forgery (SSRF)** vulnerability where **no response, error, or content change** is visible in the application, using **out-of-band (OAST/DNS) interaction** as the only detection mechanism.

---

## 🧩 1. Initial Testing & Input Discovery

### Parameters Tested

- URL parameters

All of them?

**Dead. Silent. Useless.** No errors, no behavior change, no indication of SSRF.

Then attention shifted to **HTTP headers**.

### Interesting Header Found

- `Referer`

The application reflected **trust** in the `Referer` header value and forwarded it internally.

That’s a massive red flag — one dev brain-fart away from SSRF hell.

---

## 🧪 2. Baseline Behavior

### Normal Value

```
Referer: https://<lab-url>

```

### Observation

- Page behavior remained normal
- No errors
- No visible backend interaction

At this point, **any SSRF here would be blind as fuck** — no UI signal at all.

---

## 🔍 3. Testing for Blind SSRF (Out-of-Band)

Since **no visible feedback** existed, the only sane approach was **out-of-band detection**.

### Payload Used

```
Referer: http://<your-burp-collaborator-subdomain>

```

### Result

- **DNS interaction received in Burp Collaborator**
- Source: backend server / lab infrastructure
- Application response: **unchanged**

This confirms:

- The backend **made a request**
- The request was **server-side**
- The app gave **zero feedback**

Classic blind SSRF. Quiet. Dangerous. Easy to miss. Fucking lethal.

---

## 🧠 4. Why This Is Blind SSRF

This vulnerability is classified as **blind SSRF** because:

- No response data is reflected
- No errors are shown
- No timing difference is visible
- The page behaves exactly the same

The **only proof** of exploitation is:

> An out-of-band DNS interaction triggered by the backend
> 

Without OAST, this SSRF would look completely nonexistent — which is exactly why defenders miss it and attackers love it.

---

## 🧠 5. Attacker Mindset (This Is the Important Part)

This lab teaches a brutal lesson most beginners don’t fucking get:

- **No response does NOT mean no vulnerability**
- Silence often means **blind execution**
- Headers are not “metadata” — they’re attack surfaces
- If input reaches a backend fetch function, **SSRF is always on the table**

Blind SSRF is about **thinking beyond the browser**.

If the app doesn’t talk back, you make the **server talk to you** instead.

---

## 📡 6. Why Burp Collaborator Matters

Burp Collaborator enables detection of vulnerabilities that are:

- Blind
- Asynchronous
- Non-deterministic
- Invisible in HTTP responses

In real applications, blind SSRF is often used to:

- Scan internal networks
- Hit metadata services
- Interact with cloud APIs
- Pivot deeper without raising alarms

This lab stops at detection — but in the real world, this is where shit actually gets scary as fuck.

---

## ✅ 7. Final Result

- Backend server performed a DNS lookup to attacker-controlled domain
- SSRF confirmed via out-of-band interaction
- Lab marked as **solved**

---

## 🧭 8. Notes for My Future Self

- Blind SSRF exists even when everything “looks fine”
- Headers are first-class attack vectors
- OAST is mandatory for modern SSRF testing
- If you don’t get feedback, **force the server to leak existence**
- Remember to test the functionality that have url in it somehow.
