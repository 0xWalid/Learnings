# Lab#04 **: SQL injection attack, querying the database type and version on MySQL and Microsoft**

## 📌 **1. Observation**

- The vulnerable parameter was located in the **category** field of a product listing endpoint.
- The original value was `category=Pets`. Supplying normal category values (e.g., `Pets`) loaded items as expected.
- Injecting a **single quote (`'`)** triggered an **Internal Server Error** — a strong indicator the input is placed inside a SQL string literal.
- Trying `UNION SELECT NULL, NULL --` produced internal errors when using `--` for comment; switching comment style to `#` resolved that.
- Payloads placed directly in the browser URL did not behave as expected due to browser safety/encoding; sending payloads via **Burp Suite** produced the intended server-side execution.
- **Intuition:** Input is concatenated into a SQL query without proper sanitization; UNION-based extraction may be possible after discovering column count and compatible datatypes.

---

## 🧠 **2. Hypothesis**

The backend query likely resembles:

```sql
SELECT * FROM products
WHERE category = '<user_input>';
```

Reasoning:

- A single quote breaks the query → input is inside a quoted SQL string.
- To leak DB metadata (type/version), a `UNION SELECT` injection can be used **if** we find the correct number of columns and at least one column that accepts text.
- Comment styles matter: some apps filter/handle `--` differently; `#` may work on MySQL.
- Browser encoding/safety can mask payload behavior; **must use an interceptor (Burp)** to ensure payloads hit the server unchanged.

**Goal:** Identify column count & a string-accepting column, then run a payload like:

```sql
' UNION SELECT @@version, 'x' #

```

to retrieve MySQL version from `@@version`.

---

## 🧪 **3. Test (Experiments Conducted)**

### **Test 1 — Injection Detection**

- **Input:** `'`
- **Actual:** Internal Server Error
- **Interpretation:** Confirmed SQL injection vulnerability; input breaks SQL string handling.

---

### **Test 2 — Column Count Discovery**

- **Tried:** `' UNION SELECT NULL --` and variations with `--` comment
    - **Result:** Internal Server Error (app does not accept `--` style or blocks it).
- **Change:** Replaced comment `--` with `#` and used Burp to send payloads.
- **Observed:** After switching to `#`, able to test union payloads more reliably.

*(Attempted increasing number of `NULL`s up to 3 with `--` but the same internal error persisted until switching comment style and using Burp.)*

---

### **Test 3 — Final Version Extraction**

- **Payload used (sent via Burp):**

```sql
Pets'union select @@version,'b'#
```

- **Actual Response (extracted from page):**

```sql
8.0.42-0ubuntu0.20.04.1
b

```

- **Interpretation:** The `@@version` global variable printed the MySQL server version; second column echoed the literal `'b'`, confirming the UNION succeeded and the column accepted string data.

---

> Note: Boolean-based tests were not performed for this lab — the UNION technique achieved the objective directly.
> 

---

## 📊 **4. Result**

### ✔ **Payloads & Techniques**

- Detection: `'` → Internal Server Error.
- Column / comment adjustments: `#` comment worked where `--` did not.
- Final extraction payload:

```sql
Pets'union select @@version,'b'#
```

### ✔ **Extracted Information (Proof)**

- Returned from server:

```sql
8.0.42-0ubuntu0.20.04.1
b
```

- **Conclusion:** DBMS is **MySQL 8.0.42** (Ubuntu packaging). UNION-based SQL injection is exploitable on the `category` parameter.
- **Proof of Lab Completion:** Version string displayed in application response.
- Screeshot
    
    <img width="1232" height="520" alt="image" src="https://github.com/user-attachments/assets/512faed2-dac8-45a2-ba28-3f6bdb5c2664" />


---

## 🎓 **5. Learning (Deep Reasoning)**

- **Single-quote behavior:** `'` causing an Internal Server Error strongly indicates user input is injected into a quoted SQL string. This is the fastest detection technique for string-based SQLi.
- **Comment style matters:** Some filters or SQL dialect handling in the application can block `--`or treat it specially; `#` works in MySQL. Always try alternate comment syntaxes when `--` fails.
- **Browser vs. Proxy:** Modern browsers auto-encode or sanitize certain characters; always test payloads via an intercepting proxy (Burp) to ensure server-received input matches your intended payload.
- **UNION mechanics:** To use `UNION SELECT` you must match the number of columns and compatible types. Finding that a literal string in the second column (`'b'`) rendered correctly confirmed at least one text-accepting column.
- **`@@version` utility:** MySQL exposes `@@version` as a quick way to enumerate server version; returning it via UNION is low-effort and high-confidence for determining DBMS type/version.
- **Exploit flow efficiency:** If UNION works, you can extract metadata quickly without need for time-consuming Boolean-based enumeration. Always attempt easier enumeration techniques first (e.g., global variables, metadata tables).

---

## 🔮 **6. Future Pattern Detection**

When you see these signals, suspect MySQL UNION-based SQLi:

- `'` → Internal Server Error (string literal break).
- Application reflects input or shows additional rows/products after injection attempts.
- `--` causing errors but `#` working suggests MySQL or a parser that treats `--` specially (or filters it).
- Successful UNION with `@@version` or similar global variables returns DB info.
- Payloads succeed only when sent via proxy — browser auto-sanitization was masking true behaviour.

These patterns  quickly predict MySQL backend and the most effective extraction techniques.

---

## 🧭 **7. Notes for My Future Self**

- Always test `'` first — it’s the quickest SQLi detector for string-based queries.
- If `--` fails, try `#` and test in Burp. Don’t trust browser behavior.
- Use `@@version` for a fast MySQL version disclosure via UNION.
- Confirm column count / datatypes by injecting literals (`'a'`, `'b'`) and `NULL`s.
- If UNION works, prioritize metadata extraction (version, user(), database()) before slower boolean/time techniques.
