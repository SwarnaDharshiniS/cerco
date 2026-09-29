EvoSafe / CERCO Discussion Summary

After reviewing your proposal, methodology diagram, references, dataset plan, and the CERCO architecture, the biggest conclusion is:

You already have most of the static-analysis infrastructure built. The missing publication-worthy contribution is EA Semantic Inference + EvoIR + Certification for Evolutionary Algorithms.

1. Current Status
Dataset

Completed:

✅ Category 1: Generic Benign
   - TheAlgorithms
   - Cookbook samples

✅ Category 3: DEAP EA
   - ~55 programs

✅ Category 4: Non-DEAP EA
   - pymoo
   - pygad
   - mealpy


Not completed:

⬜ Category 2: Generic Unsafe

⬜ Category 5: LLM-generated EA

⬜ Category 6: LLM-generated Non-EA

⬜ Category 7: Unsafe EA

⬜ Category 8: Unsafe Non-EA


Recommendation:

Pause dataset collection.


The repository already has enough programs to begin architecture development and experimentation.

2. Original Proposed Methodology

Your methodology diagram:

Python / Notebook Input
           |
       AST + CFG
           |
   +-------+-------+
   |               |
Safety         EA Inference
   |               |
   +-------+-------+
           |
         EvoIR
           |
     Certification
           |
SAFE / UNKNOWN / UNSAFE


My assessment:

This architecture is correct.


I would not redesign it.

3. Mapping CERCO to EvoSafe

Initially I assumed you had only AST/CFG.

After seeing the repository architecture:

CERCO already provides:

✅ AST
✅ CFG
✅ Taint Analysis
✅ Capability Analysis
✅ Resource Analysis
✅ Decision Engine
✅ Manifest Generation
✅ Safety IR
✅ Notebook Parsing
✅ Execution Orchestrator
✅ Sandbox
✅ Distributed Scheduler


Therefore:

CERCO ≈ 70-80% of EvoSafe already implemented

4. CERCO Architecture Breakdown
Layer 1: Parser Layer

Folder:

parser/


Contains:

ast_parser.py
notebook_execution_parser.py


Purpose:

Python Source
      ↓
AST


and

Notebook
      ↓
Execution DAG


Output:

{
  "type": "FunctionDef",
  "name": "fitness"
}


This is a frontend only.

No interpretation.

Layer 2: CFG Layer

Folder:

cfg/


Contains:

cfg_builder.py


Purpose:

AST
      ↓
CFG


Handles:

if
for
while
break
continue
return
raise
try/except


Produces:

Basic Blocks


and

Control Flow Graph


using:

networkx.DiGraph


This is sufficient for EvoSafe.

No need to replace it with py2cfg.

Layer 3: Safety Analysis Layer

Folder:

analysis/

Capability Analysis

Purpose:

What can this code do?


Detects:

FS   Filesystem
NET  Network
PROC Process
DYN  Dynamic Execution


Examples:

os.system()


↓

{
    "capability":"PROC"
}

Taint Analysis

Purpose:

Can attacker-controlled data reach dangerous sinks?


Example:

cmd=input()
os.system(cmd)


↓

{
    "source":"input",
    "sink":"os.system"
}


Already:

flow-sensitive
interprocedural
bounded expansion


which is more than enough.

Resource Analysis

Purpose:

Can this code consume excessive resources?


Detects:

Infinite loops
Recursion
Large allocations
Loop depth
Call depth


Example:

while True:


↓

HIGH RISK


Recommendation:

Keep current implementation.

Do not implement:

AARA
Loop Bound Solvers
Recurrence Solving


Those are entire research areas by themselves.

5. Decision Engine

Folder:

analysis/decision/


Current:

SAFE
CONDITIONALLY_SAFE
UNSAFE


Recommendation:

Change to:

SAFE
UNKNOWN
UNSAFE


because static analysis often cannot prove correctness.

Example:

exec(code_from_network)


↓

UNSAFE


Example:

complex reflection


↓

UNKNOWN

6. SafetyIR

Current:

SafetyIR


Contains:

FunctionNode
LoopNode
CFGNode
CapabilityNode
TaintFlowEdge


This is extremely important.

7. The Biggest Insight

You do NOT need to create EvoIR from scratch.

Instead:

SafetyIR
      ↓
Extend
      ↓
EvoIR


Current Nodes:

FunctionNode
LoopNode
CapabilityNode
CFGBlockNode


Add:

PopulationNode
SelectionNode
MutationNode
CrossoverNode
EvaluationNode
ReplacementNode
TerminationNode


This instantly creates EvoIR.

8. Missing Piece: EA Semantic Inference

This is the most important conclusion.

Current CERCO

Understands:

Program Structure


but not

Evolutionary Meaning

New Module

Create:

analysis/
    ea/


Suggested structure:

analysis/
    ea/
        detector.py
        roles.py
        evidence.py

9. Seven EA Roles

Recommended roles:

1. Population
2. FitnessEvaluation
3. Selection
4. Mutation
5. Crossover
6. Replacement
7. Termination


Example

Input:

offspring = toolbox.select(pop)


Output:

{
  "role":"Selection",
  "confidence":0.95
}


Input:

mutate(individual)


↓

{
  "role":"Mutation",
  "confidence":0.91
}

10. Why This Is Novel

Many things already exist:

AST Analysis
CFG Analysis
Call Graphs
Taint Analysis
Sandboxing


Existing systems:

PyCG
Scalpel
Mopsa
SAST tools


already do that.

What they do NOT do:

Framework-Independent EA Inference


or

Certification of Evolutionary Algorithms


or

Certification of LLM-generated EAs


This is where the publication value lies.

11. How References Should Be Used
PyCG

Use for:

Call graph concepts


Do not reimplement.

Scalpel

Use for:

AST analysis
Program modeling


Closest research ancestor.

Mopsa

Use for:

SAFE / UNKNOWN / UNSAFE reasoning


Do not attempt full abstract interpretation.

Resource Papers

References:

AARA
Hybrid AARA
Loop Bounds
Recurrence Equations


Use only as motivation.

Do not implement them.

12. Publication Potential

Current CERCO alone:

GECCO Main Track
20-40%


Reason:

Mostly engineering infrastructure.


CERCO + EA Inference:

GECCO Workshop
70-90%

EvoStar
70-85%


CERCO + EA Inference + EvoIR + LLM EA Certification:

GECCO Main
Possible


depending on evaluation quality.

13. Recommended Development Roadmap
Sprint 1

Build:

analysis/ea/


Implement:

Population
Fitness
Selection
Mutation
Crossover
Replacement
Termination


Rule-based detection.

Sprint 2

Extend:

SafetyIR
      ↓
EvoIR


Add:

EA Role Nodes
Evidence Nodes

Sprint 3

Integrate Certification

Input:

Safety Results
+
EA Results


Output:

SAFE
UNKNOWN
UNSAFE

Sprint 4

Evaluate on:

DEAP
pymoo
mealpy
PyGAD


Measure:

EA Detection Accuracy
Role Accuracy
False Positives

Sprint 5

Add:

LLM-generated EA


dataset.

This can become the strongest experimental section.

Final Verdict

If I were your reviewer, I would say:

CERCO already solves the infrastructure problem.


Your next 80% effort should NOT go into:

CFG
Taint
Resources
Call Graphs
Sandboxing


Those are already present.

Your next 80% effort should go into:

EA Semantic Inference
+
EvoIR
+
Certification of EA Programs
+
LLM-generated EA Analysis


That is where the novelty, thesis contribution, and potential GECCO/EvoStar acceptance are most likely to come from.
