## 📌 **1. Observation**

- The vulnerable parameter was the **`category`** parameter on the product listing page.
- Normal request:
    
    ```
    category=Pets
    ```
    
    → Products displayed normally.
    
- Injecting a **single quote (`'`)** caused an **Internal Server Error**, indicating:
    - User input is embedded directly into an SQL string.
    - No proper sanitization or escaping is applied.
- This confirmed a **SQL injection vulnerability**.
- The lab objective was **not** to extract data, but to determine how many columns the backend query returns.

---

## 🧠 **2. Hypothesis**

Likely backend query structure:

```sql
SELECT column1, column2, column3
FROM products
WHERE category = '<user_input>';
```

Reasoning:

- Since the input is inside a string literal, breaking it with `'` causes an error.
- A `UNION SELECT` can be used **only if**:
    - The number of columns in the injected query **matches** the number of columns in the original query.
- If the number of columns does **not** match:
    - The database throws an error.
- If the number **does** match:
    - The error disappears and the page loads normally.

**Goal:**

Find the exact number of columns by adjusting the number of `NULL` values in a `UNION SELECT`.

---

## 🧪 **3. Test (Experiments Conducted)**

### **Test 1 — Confirm SQL Injection**

**Payload:**

```sql
'
```

**Result:**

- Internal Server Error.
- Confirms SQL injection vulnerability.

---

### **Test 2 — UNION SELECT With Incremental NULLs**

Started adding `NULL` values to a `UNION SELECT` statement.

Why `NULL`?

- `NULL` is compatible with **any datatype**.
- This avoids datatype mismatch errors while testing column count.

Tried payloads like:

```sql
Pets' UNION SELECT NULL--
Pets' UNION SELECT NULL,NULL--
```

These caused errors → column count still incorrect.

---

### **Test 3 — Successful Column Count Detection**

**Working payload:**

```sql
Pets' UNION SELECT NULL,NULL,NULL--
```

**Result:**

- Internal Server Error disappeared.
- Page loaded successfully.
- Lab completion animation appeared.
- Screenshot:
      <img width="1232" height="301" alt="image" src="https://github.com/user-attachments/assets/18ee563d-a457-4017-9c60-00ea4cc29db4" />


**Conclusion:**

> The original query returns 3 columns.
> 

At this point, the lab was solved.

---

## 📊 **4. Final Payload Used**

```sql
Pets' UNION SELECT NULL,NULL,NULL--
```

✔ Confirms that the backend query returns **three columns**.

---

## 🎓 **5. Clear Explanation**

### **Why does this work?**

- `UNION` combines the results of two queries.
- SQL requires both queries to have:
    - The **same number of columns**
    - Compatible datatypes in each column position
- When the number of columns is wrong → database error.
- When the number is correct → query executes normally.

### **Why use NULL?**

- `NULL` can represent any datatype.
- This avoids worrying about whether a column expects text, numbers, etc.
- It’s the safest way to count columns.

---

## 🧠 **6. Key Learning**

- Determining column count is a **mandatory step** before any UNION-based SQL injection.
- Two common methods exist:
    1. `ORDER BY` method
    2. `UNION SELECT NULL,NULL,...` method (used here)
- Error disappearing = **success signal**.
- Once column count is known, you can:
    - Identify which columns accept text
    - Replace `NULL` with real values
    - Extract data in later labs

---

## 🔮 **7. Notes for Future Me**

- Always start with `'` to confirm SQL injection.
- If the lab mentions UNION:
    - Immediately determine column count.
- Use incremental `NULL` values:
    
    ```
    NULL
    NULL,NULL
    NULL,NULL,NULL
    
    ```
    
- When the page loads normally → stop counting.
- Remember:
    
    > Column count must match exactly, or UNION will fail.
    >
