## 📌 **1. Observation**

- The vulnerable parameter was **`category`** in the product filtering feature.
- Normal values such as `Accessories` loaded products correctly.
- Injecting a **single quote (`'`)** caused abnormal behavior, confirming:
    - User input is embedded inside a quoted SQL string.
    - No proper sanitization or escaping is applied.
- This lab did **not** require extracting data from tables.
- The objective was to identify **which column can render text** in a UNION query.

---

## 🧠 **2. Hypothesis**

Likely backend query structure:

```sql
SELECT col1, col2, col3
FROM products
WHERE category = '<user_input>';
```

**Reasoning:**

- UNION-based SQL injection requires:
    - The **exact number of columns**
    - **Datatype compatibility** across each column
- Therefore:
    - Each column must be tested individually with a string literal.
    - The column that executes without error is the one that accepts text.

**Goal:** Identify the string-compatible column and inject the lab-provided string.

---

## 🧪 **3. Tests (Experiments Conducted)**

### **Test 1 — Confirm column count**

After basic testing, a UNION query with **three columns** executed without errors.

**Conclusion:**

✅ The original query returns **3 columns**.

---

### **Test 2 — Identify the text-accepting column**

**Payload used:**

```sql
Accessories' UNION SELECT NULL,'a',NULL--

```

**Why this works:**

- `NULL` is datatype-agnostic in Oracle.
- `'a'` is a string literal.
- Placing the string in the **second column** caused no error.

**Conclusion:**

🧠 **Column 2 accepts string data**

This is the key insight required to solve the lab.

---

### **Test 3 — Inject the required string**

The lab required displaying the following string:

```
27o7HVGK

```

**Final payload:**

```sql
Accessories' UNION SELECT NULL,'27o7HVGK',NULL--

```

**Result:**

- Query executed successfully.
- Application accepted the payload.
- The lab displayed the **“Lab Solved”** animation.
- Screenshot
    <img width="1275" height="258" alt="image" src="https://github.com/user-attachments/assets/7f3a0063-a5d4-43e4-9c56-31a91ad685b0" />

    

---

## 📊 **4. Result**

### ✔ **Final Working Payload**

```sql
Accessories' UNION SELECT NULL,'27o7HVGK',NULL--

```

### ✔ **Confirmed Facts**

- Vulnerable parameter: `category`
- Total columns: **3**
- Text-compatible column: **2**
- No data extraction required
- Lab solved via successful UNION execution

---

## 🎓 **5. Learning (Reference When Feeling Lost)**

This lab focuses on **datatype reasoning**, not data extraction.

**Key takeaways:**

- UNION-based SQL injection always requires:
    - Correct column count
    - Correct datatype placement
- Strings must be placed in string-compatible columns
- Numeric columns reject string input
- `NULL` is extremely useful:
    - It can safely fill columns when the datatype is unknown
- The purpose of this lab is **column discovery**, not exploitation.

**Mental shortcut:**

> If a string does not cause an error in a column, that column accepts text.
> 

---

## 🔮 **6. Future Notes**

When solving **“find a column containing text”** labs:

1. Always determine the column count first.
2. Use `NULL` in all columns except one.
3. Rotate the string literal through each column:
    - `NULL,'a',NULL`
    - `'a',NULL,NULL`
    - `NULL,NULL,'a'`
4. The column that does not error is the string-compatible column.
5. Replace `'a'` with the required lab string.
6. Avoid overcomplicating the process.

---

## 🧭 **7. Notes for My Future Self**

- `NULL` is a safe placeholder during UNION testing.
- Test one column at a time.
