# Budgetsystemet GOrdian

Fullstack Golang application that handles the budget of Datasektionen.

Live at [budget.datasektionen.se](https://budget.datasektionen.se).

# API

**API documentation** can be found here: **Look down**

## List all Cost Centres

<details>
    <summary>
        <code>GET</code> <code><b>/api/CostCentres</b></code> <code>(gets all CCs)</code>
    </summary>

### Parameters

None

### Responses

```JSON
[
  {
    "CostCentreID":21,
    "CostCentreName":"Ada",
    "CostCentreType":"committee"
  }
]
```

</details>

## List all Secondary Cost Centres of a Cost Centre

<details>
    <summary>
        <code>GET</code> <code><b>/api/SecondaryCostCentres?id={CCid}</b></code> <code>(gets all SCC given CC id)</code>
    </summary>

### Parameters

> | name   | type     | data type    | description                      |
> | ------ | -------- | ------------ | -------------------------------- |
> | `CCid` | required | int ($int64) | The id of a specific Cost Centre |

### Responses

```JSON
[
  {
    "CostCentreID":1,
    "SecondaryCostCentreID":3,
    "SecondaryCostCentreName":"Allmänt"
  }
]
```

</details>

## List all Budget Lines of a Secondary Cost Centre

<details>
    <summary>
        <code>GET</code> <code><b>/api/BudgetLines?id={SCCid}</b></code> <code>(gets all Budget Lines given SCC id)</code>
    </summary>

### Parameters

> | name    | type     | data type    | description                                |
> | ------- | -------- | ------------ | ------------------------------------------ |
> | `SCCid` | required | int ($int64) | The id of a specific Secondary Cost Centre |

### Responses

```JSON
[
  {"SecondaryCostCentreID":3,
    "BudgetLineID":33,
    "BudgetLineName":"Mat till planeringsmöten",
    "BudgetLineAccount":"4029",
    "BudgetLineIncome":0,
    "BudgetLineExpense":-4400,
    "BudgetLineComment":"Ny för i år, 4"
  }
]
```

</details>

# Entities

Each entry in the system consists of the following entities.
There are three elementary entities in the
system, Cost centres, Secondary cost centres and Budget lines.

## Cost Centre

A _Cost Centre_ is called _Resultatställe_ in Swedish. It can be typed as a Project (Projekt), ProjectX (Projekt vars budget inte påverkar året), Partition (Partition), Committee (Nämnd) or Other (Övrigt).
They are the main budget divisions.

## Secondary cost centre

A _Secondary cost centre_ is part of a Cost centre. It can be an event or otherwise differentiable part of the Cost centre.
Each Secondary cost centre contains the Cost centre it is connected to.

## Budget line

A _Budget line_ is the smallest part of a budget, belonging to a Secondary cost centre.
Each Budget line centre contains the Secondary cost centre it is connected to.
A Budget Line also contains the following.

### Income and Expense

The prediction of what someone expects to earn or spend.
A Budget Line never has an Income and an Expense at the same time.

### Account

_Account_ is used to assist with the bookkeeping

### Comment

A _Comment_ is used to further clarify the use of a Budget line

# Running locally

- Clone repo
- Install docker
- Create dockerimage:

```sh
docker compose up --build --watch
```

- Run dockerimage

- Ask Kassör for an updated budget spreadsheet or use the sample one found under web > static > budgets
- Go to http://localhost:3000/admin and upload it
- To be able to see resultatrapport, you need to ask dsys for a database dump of cashflow and then write:

```sh
docker compose exec -iT cashflow-db  pg_restore --no-owner -U cashflow -d cashflow -h localhost  < path/to/cashflow_dump.sql
```

- ???
- Profit!

## Troubleshooting

### Error getting credentials

If you get the following error:

```
error getting credentials - err: exec: "docker-credential-desktop": executable file not found in $PATH, out: ``
```

Try renaming "credsStore" to "credStore" in ~/.docker/config.json

https://forums.docker.com/t/docker-credential-desktop-exe-executable-file-not-found-in-path-using-wsl2/100225/5

### Other problems

1. Ask Douglas
2. Ask dsys
3. Pray

# Very nice money budget
