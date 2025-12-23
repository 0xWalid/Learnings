## 🎯 Objective

Exploit a **SQL injection vulnerability in an XML-based POST request** by **bypassing keyword filters using XML entity encoding**, allowing extraction of **usernames and passwords** despite active WAF-style defenses.

---

## 🧩 1. Initial Testing & Vulnerability Identification

### Parameters Tested

- URL parameters
- Product parameters

No SQL injection behavior was observed in standard URL or product-based inputs.

---

### XML-Based Request Identified

While analyzing application functionality, a **POST request** used to check stock availability was identified.

This request submitted data in **XML format**, making it a high‑value target for injection testing.

### Key Observation

- Input was processed server-side from XML tags
- Security controls were applied **before SQL execution**
- This suggested a **filter-based defense**, not a hardened query

---

## 🧠 2. Identifying the Injection Point

### Injectable XML Parameter

```xml
<storeId>
```

### Initial Test

```xml
<storeId>1 UNION SELECT</storeId>
```

### Result

- Application responded with **“Attack detected”**
- Confirms:
    - Input is reaching a SQL query
    - Keywords like `UNION`, `SELECT`, and `'` are actively filtered

This confirms **SQL injection exists**, but is **protected by keyword filtering**.

---

## 🚧 3. Understanding the Filter Behavior

### What Was Blocked

- `UNION`
- `SELECT`
- Single quote (`'`)

### Important Insight (Mindset Shift)

> Filters often inspect raw input, not the post‑parsed content.
> 

This means:

- XML parsers decode entities **after** filtering
- Encoded payloads can pass filters and execute normally in SQL

This is a **critical advantage**:

- No need for time delays
- No need for blind logic
- Direct data extraction becomes possible

---

## 🧠 4. Filter Bypass via XML Entity Encoding

### Strategy

- Encode SQL keywords using **numeric XML entities**
- Encode single quotes using `&apos;`
- Let the XML parser reconstruct the payload **after** filter inspection

---

## ✅ 5. Working Payload (Filter Bypass)

```xml
<storeId>
1&#85;&#110;&#105;&#111;&#110;&#83;&#101;&#108;&#101;&#99;&#116;
username ||&apos; +&apos; || password FROM users
</storeId>

```

### Decoded by Server As

```sql
1 UNION SELECT username||' + '|| password FROM users

```

---

## 🎯 6. Successful Data Extraction

### Result

- “Attack detected” message **did not appear**
- Application returned:
    - **Usernames**
    - **Passwords**
- Data was reflected directly in the response

This confirms:

- Filter successfully bypassed
- SQL query executed normally
- Output was reflected in the application

---

## 📊 7. Final Result

```sql
335 units
administrator + jc1023elqthareue3d67
wiener + cd0rzm0v4bujgasasz8i
carlos + w1it05wenc2tbwsta7n8
```

- Logged in using extracted credentials
- Application confirmed administrator access
- Lab marked as **Solved**
- ![Uploading image.png…]()


---

## 🔮 8. Key Takeaways (Important)

### Why XML Encoding Is Powerful

- Filters inspect **raw input**
- XML entities are decoded **after filtering**
- SQL engine receives **fully reconstructed keywords**

### When to Think About XML Encoding

- Input is sent as XML
- Keywords are blocked but errors are not shown
- “Attack detected” style responses appear
- UNION-based injection *should* work but doesn’t

---

## 🧭 9. Notes for My Future Self

- XML inputs are **high-risk injection points**
- Keyword filtering ≠ SQL safety
- XML entity encoding is a **filter killer**
- Always inspect request formats, not just parameters
- If UNION is blocked, don’t quit — **encode it**
