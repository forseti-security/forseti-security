---
title: Scanner
order: 004
---

# {{ page.title }}

Forseti Scanner scans the inventory data according to the rules (policies) you defined.

You can learn about how to define custom rules [here]({% link _docs/latest/configure/scanner/rules.md %}).

## Running Forseti Scanner

Forseti Scanner works on a data model, so before you start using Scanner, you'll select a model to use. 

Instructions on how to create a model can be found [here]({% link _docs/latest/use/model.md %}).

To configure which scanners to run, see 
[Configuring Forseti: Configuring Scanner]({% link _docs/latest/configure/configuring-forseti.md %}#configuring-scanner).


#### Selecting a data model

```bash
$ forseti model use <YOUR_MODEL_NAME>
```

#### Running the scanner

```bash
$ forseti scanner run
```

Scanner produces violations and stores them in the violation table in the database. 
To receive notifications for violations, run the 
[Forseti Notifier]({% link _docs/latest/use/notifier.md %}).