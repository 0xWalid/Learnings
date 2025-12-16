## 📌 **1. Observation**

- The vulnerable parameter was **`category`** in the product filtering functionality.
- Supplying normal category values such as `Gifts` returned valid product listings.
- Injecting a **single quote (`'`)** altered application behavior, confirming that:
    - User input is concatenated into a SQL query
    - The input is placed inside a **quoted string context**
- Previous UNION-based testing confirmed:
    - The query returns **2 columns**
    - The **second column** accepts **string data**
- The lab explicitly stated:
    - The target table is **`users`**
    - The goal is to retrieve the **administrator** credentials
- Only **one column** of the UNION result is rendered in the response, requiring multiple values to be combined into a single column.

---

## 🧠 **2. Hypothesis**

Likely backend query structure:

```sql
SELECT col1, col2
FROM products
WHERE category='<user_input>';
```

Reasoning:

- UNION injection is possible due to lack of input sanitization.
- Since only one column is reflected in the response:
    - Username and password must be **concatenated into a single string**
- The database uses **Oracle-style concatenation**, which relies on:
    - The `||` operator for combining strings

**Goal:**

Combine `username` and `password` into one output column and retrieve administrator credentials.

---

## 🧪 **3. Tests (Experiments Conducted)**

### **Test 1 — Confirm column count**

Payload used:

```sql
'UNION SELECT NULL,NULL--
```

- Result: No error
- Conclusion: The query returns **2 columns**

---

### **Test 2 — Identify string-compatible column**

Earlier testing confirmed:

- The **second column** accepts string data
- This column will be used to display concatenated output

---

### **Test 3 — Retrieve multiple values in a single column**

Payload used:

```sql
Gifts' UNION SELECT NULL, username||'+'||password FROM users--
```

Explanation:

- `username||'+'||password` concatenates:
    - Username
    - A visible separator (`+`)
    - Password
- `NULL` is used in the first column to maintain column count compatibility
- Oracle’s `||` operator ensures proper string concatenation

---

## 📊 **4. Result**

- The application returned a combined string containing: **`administrator 2mxdy1qfh55wrln6nu4s`**
    - The **administrator username**
    - The **administrator password**
- The lab validated successful exploitation and was marked as **solved**
- Screenshot
<img width="1234" height="551" alt="image" src="https://github.com/user-attachments/assets/6ecfbfdd-b8b0-46dd-8536-c3febb7264fc" />

---

## 🎓 **5. Learning (Core Concept)**

This lab teaches an essential real-world technique:

- When only **one column is reflected**, you must:
    - Combine multiple fields into a **single output string**
- Key points:
    - Column count must match exactly
    - Datatypes must be compatible
    - Database-specific concatenation syntax matters

Common concatenation syntax:

- **Oracle / PostgreSQL:** `column1 || column2`
- **MySQL:** `CONCAT(column1, column2)`

Understanding this avoids trial-and-error guessing and enables efficient exploitation.

---

## 🔮 **6. Future Notes (Quick Recall Guide)**

When facing similar labs or real-world targets:

1. Identify reflected columns
2. Confirm which column accepts strings
3. If only one column is visible:
    - Concatenate required values into that column
4. Use correct DBMS syntax:
    - Oracle → `||`
    - MySQL → `CONCAT()`
5. Add a clear separator between values for readability
6. Verify results in the application response

---

## 🧭 **7. Notes for My Future Self**

- Always adapt concatenation syntax to the database type
- If output is limited, combine values — don’t force multiple columns
- `NULL` is useful for padding unused columns
