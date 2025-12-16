## 🧩 1. Initial Testing & Vulnerability Identification

### Parameters Tested

- `category`
- `productId`

Both parameters were tested with a single quote (`'`) and **no abnormal behavior** was observed.

### Cookie-Based Testing

While inspecting the HTTP request, a cookie parameter named **`TrackingId`** was identified.

### Observation

- Normal `TrackingId` → Page displays **"Welcome back!"**
- Adding a single quote (`'`) → **"Welcome back!" disappears**

This behavior indicates:

- User input is being processed by the database
- SQL errors are suppressed
- The application logic depends on whether the SQL query evaluates to **TRUE or FALSE**

This confirms a **blind SQL injection vulnerability with conditional responses**.

---

## 🧠 2. Understanding Why This Is Blind SQL Injection

In this lab:

- No database errors are shown
- No query results are reflected on the page
- The only feedback channel is **page behavior**

This means:

- We cannot use `UNION SELECT` to retrieve data directly
- We must rely on **boolean logic** (TRUE / FALSE conditions)

The application likely executes a query similar to:

```sql
SELECT trackingId FROM tracking
WHERE trackingId = '<TrackingId>';
```

If the query returns **any rows**, the application displays **"Welcome back!"**.

---

## 🧪 3. Confirming Boolean Control

### TRUE Condition

```sql
TrackingId=... ' AND '1'='1
```

### FALSE Condition

```sql
TrackingId=... ' AND '1'='2
```

### Result

- TRUE → “Welcome back!” appears
- FALSE → Message disappears

This confirms full control over boolean logic in the SQL query.

---

## ❌ 4. Why UNION Does Not Work Here

`UNION` attacks are useful only when:

- Query results are **reflected in the response**

In this lab:

- The application never displays query output
- It only checks whether rows exist

Therefore:

- `UNION SELECT` provides no benefit
- Boolean-based payloads are required

---

## 🧠 5. Why Some Payloads Failed

### ❌ Invalid Payload Example

```sql
AND SELECT username FROM users WHERE username='administrator'

```

**Why it fails:**

- `AND` expects a boolean expression
- `SELECT username FROM users` returns rows, not TRUE/FALSE
- SQL syntax is invalid in this context

---

## ✅ 6. Why This Payload Worked

```sql
TrackingId=...'
AND (SELECT 'administrator' FROM users LIMIT 1)='administrator'

```

### Explanation

- The subquery returns a **constant value**
- `LIMIT 1` ensures exactly one row is returned
- `'administrator' = 'administrator'` evaluates to TRUE

This confirms the **existence** of the `administrator` user.

---

## 🔎 7. SQL Functions Used (Core Concepts)

### 1️⃣ `EXISTS`

### Syntax

```sql
EXISTS (SELECT 1 FROM table WHERE condition)
```

### Purpose

- Returns TRUE if at least one row exists
- Ideal for blind SQL injection

---

### 2️⃣ `LENGTH()`

### Syntax

```sql
LENGTH(string)
```

### Payload Used

```sql
TrackingId=...'
AND LENGTH((SELECT password FROM users WHERE username='administrator'))='20'
```

### Logic

- Determines password length
- Required before extracting characters

---

### 3️⃣ `SUBSTRING()`

### Syntax

```sql
SUBSTRING(string, position, length)
```

### Example Payload

```sql
TrackingId=...'
AND SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1)='a'

```

### Logic

- Extracts one character at a time
- Each request tests a TRUE/FALSE condition

---

## 🧪 8. Password Extraction with Burp Intruder

### Payload Used

```sql
TrackingId=...'
AND SUBSTRING((SELECT password FROM users WHERE username='administrator'),§1§,1)='§a§'

```

### Intruder Configuration

- §1§ → Numbers `1–20` (character position)
- §a§ → Alphanumeric characters (`a–z`, `0–9`)
- Attack type: **Cluster Bomb**

### Analysis Method

- Sort responses by length
- Identify responses containing **"Welcome back!"**

Each TRUE response reveals one correct character.

---

## 📊 9. Final Result

```
Username: administrator
Password: j9emikunwxgnk0dm4upj
```

- Logged in successfully
- Application confirmed administrator access
- Screenshot
  <img width="1281" height="260" alt="image" src="https://github.com/user-attachments/assets/70b1f1dd-2382-46e7-a3b6-90d894f01d09" />


---

## 🔮 10. Future Testing Notes (Important)

### When Testing SQL Injection:

1. Test **all inputs**:
    - URL parameters
    - POST data
    - Cookies
    - Headers
2. Decide attack type:
    - Output visible → UNION
    - No output → Blind SQLi
3. Blind SQLi workflow:
    - Prove boolean control
    - Confirm data existence
    - Find data length
    - Extract character-by-character
    - Automate early
4. Common mistakes to avoid:
    - Forgetting `LIMIT 1`
    - Using UNION when output is not reflected
    - Skipping length detection
    - Not closing quotes properly

---

## 🧭 11. Notes for My Future Self

- Blind SQLi is logic-based, not output-based
- Always force subqueries to return one row
- Boolean responses are powerful enough to extract full credentials
- Automation is essential for reliability
- If stuck, re-check assumptions about query structure
