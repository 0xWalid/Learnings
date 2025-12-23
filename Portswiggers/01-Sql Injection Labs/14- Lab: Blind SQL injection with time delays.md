## 🎯 Objective

Exploit a **blind SQL injection vulnerability using time delays** to confirm SQL injection by triggering a **measurable delay in server response**, without retrieving any database information.

---

## 🧩 1. Initial Testing & Vulnerability Identification

### Parameters Tested

- URL parameters
- POST parameters
- Cookie parameters

All parameters were tested with a single quote (`'`) and **no abnormal behavior** was observed.

### Cookie-Based Testing

While inspecting the HTTP request, a cookie parameter named **`TrackingId`** was identified.

### Observation

- Normal `TrackingId` → Application behaves normally
- Adding a single quote (`'`) → **No visible change**
- No error messages
- No content differences

At this point, both **error-based** and **boolean-based** SQL injection appeared unavailable.

---

### 🔴 IMPORTANT — Mindset Shift

> When an application shows no errors and no content differences, it does not mean SQL injection is impossible.
> 

This is the correct moment to switch from:

- *Output-based thinking*
    
    to:
    
- *Side-channel thinking*

**Time is still observable.**

This mindset allows detection of SQL injection even when the application appears completely silent.

---

## 🧠 2. Switching to Time-Based Blind SQL Injection

Since no visible feedback was available, a **time-delay payload** was used to determine whether injected SQL was still executed by the backend.

### Payload Used

```sql
'|| pg_sleep(10)--

```

### Injection Point

```
Cookie: TrackingId=<value>'||pg_sleep(10)--

```

---

## 🧪 3. Confirming Time Delay Execution

### Result

- The server response was delayed by approximately **10 seconds**
- The delay was **consistent and repeatable**
- Page content remained **exactly the same**
- No error messages were displayed

This confirms:

- User input is executed within a SQL query
- The database supports `pg_sleep()` (PostgreSQL)
- The application is vulnerable to **blind SQL injection using time delays**

---

## 🧠 4. Why This Is Blind SQL Injection

In this lab:

- No SQL errors are displayed
- No query output is reflected
- No boolean differences are observable

The **only feedback channel** is **response time**.

Therefore:

- `UNION SELECT` is useless
- Error-based SQLi is impossible
- Conditional logic is unnecessary for this lab

A **simple, unconditional delay** is sufficient to confirm exploitation.

---

## ✅ 5. Lab Completion Condition

Unlike information-retrieval labs, this lab requires only:

- Proof that attacker-controlled SQL can trigger a **measurable delay**

Once the 10-second delay was confirmed:

- The lab was **immediately marked as solved**
- No further exploitation was required

---

## 📊 6. Final Result

- SQL injection confirmed via time delay
- No data extraction required
- Lab marked as **Solved**
- Screenshot:
-   <img width="1234" height="216" alt="image" src="https://github.com/user-attachments/assets/c7b90587-0bc0-43b9-b4ac-d905032a51e2" />


---

## 🔮 7. Future Testing Notes (Important)

### When Testing SQL Injection:

1. Always test **all inputs**:
    - URL parameters
    - POST data
    - Cookies
    - Headers
2. If:
    - No errors
    - No output differences
        
        → **Immediately test time delays**
        
3. Time-based SQLi is useful when:
    - Errors are suppressed
    - Responses are static
4. Even a **single confirmed delay** is a valid vulnerability

---

## 🧭 8. Notes for My Future Self

- Silence does not equal security
- Time is a reliable side channel
- Cookies are common blind SQLi entry points
- Not all labs require data extraction
- Confirming execution is sometimes enough
