import os
import sys
import json
import warnings

import numpy  as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")   # needed in environments without a display
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection  import train_test_split, StratifiedKFold, cross_val_score
from sklearn.preprocessing    import StandardScaler
from sklearn.linear_model     import LogisticRegression
from sklearn.ensemble         import RandomForestClassifier
from sklearn.metrics          import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, classification_report, confusion_matrix
)

from config      import (
    DATASET_PATH, TARGET_COLUMN, DROP_COLUMNS,
    FEATURE_COLUMNS, TEST_SIZE, RANDOM_STATE, MODELS_DIR
)
from model_utils import save_model

warnings.filterwarnings("ignore")

def print_header(step: int, title: str):
    print(f"\n{'─'*60}")
    print(f"  Step {step}: {title}")
    print(f"{'─'*60}")

# STEP 1: Load Data
def load_data() -> pd.DataFrame:
    print_header(1, "C:\Users\Hp\Downloads\phising.csv")

    if not os.path.exists("C:\Users\Hp\Downloads\phising.csv"):
        print(f"\n  ERROR: Could not find the dataset at: {"C:\Users\Hp\Downloads\phising.csv"}")
        print("\n  Make sure 'phishing.csv' is Sin the same folder as this script.")
        sys.exit(1)

    df = pd.read_csv("C:\Users\Hp\Downloads\phising.csv")

    print(f"  File loaded   : {"C:\Users\Hp\Downloads\phising.csv"}")
    print(f"  Shape         : {df.shape[0]:,} rows × {df.shape[1]} columns")
    print(f"  Missing values: {df.isnull().sum().sum()}")

    return df

# STEP 2: Preprocess
def preprocess(df: pd.DataFrame):
    print_header(2, "Preprocessing")

    df = df.drop(columns=DROP_COLUMNS, errors="ignore")
    print(f"  Dropped columns : {DROP_COLUMNS}")

    # Separate features and target
    X = df[FEATURE_COLUMNS].copy()
    y = df[TARGET_COLUMN].copy()

    # Handle any missing values 
    if X.isnull().sum().sum() > 0:
        X = X.fillna(X.median())
        print("  Filled missing values with column medians.")
    else:
        print("  No missing values — dataset is clean.")

    # Show class distribution
    counts = y.value_counts()
    total  = len(y)
    print(f"\n  Class distribution:")
    print(f"    Legitimate ( 1) : {counts.get( 1, 0):>6,}  ({counts.get( 1,0)/total*100:.1f}%)")
    print(f"    Phishing  (-1)  : {counts.get(-1, 0):>6,}  ({counts.get(-1,0)/total*100:.1f}%)")
    print(f"    Total           : {total:>6,}")

    return X, y


# STEP 3: Train / Test Split
def split_data(X, y):
    print_header(3, "Splitting Data (80% Train / 20% Test)")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size    = TEST_SIZE,
        random_state = RANDOM_STATE,
        stratify     = y    # keeps same class ratio in both sets
    )

    print(f"  Training set : {len(X_train):,} samples")
    print(f"  Test set     : {len(X_test):,} samples")

    return X_train, X_test, y_train, y_test


# STEP 4: Feature Scaling
def scale_features(X_train, X_test):
    print_header(4, "Feature Scaling (StandardScaler)")

    # IMPORTANT: fit only on training data to avoid data leakage
    scaler     = StandardScaler()
    X_train_s  = scaler.fit_transform(X_train)  
    X_test_s   = scaler.transform(X_test)         
    print("  Scaler fitted on training data only (no data leakage).")

    return X_train_s, X_test_s, scaler


# STEP 5: Train Models
def train_models(X_train_s, y_train) -> dict:
    print_header(5, "Training Both Models")

    models = {
        "Logistic Regression": LogisticRegression(
            max_iter     = 1000,
            C            = 1.0,
            solver       = "lbfgs",
            random_state = RANDOM_STATE,
            n_jobs       = -1,
        ),
        "Random Forest": RandomForestClassifier(
            n_estimators      = 200,
            max_depth         = None,
            min_samples_split = 2,
            random_state      = RANDOM_STATE,
            n_jobs            = -1,
        ),
    }

    trained = {}
    for name, model in models.items():
        print(f"\n  Training {name}...", end=" ", flush=True)
        model.fit(X_train_s, y_train)
        print("✓ Done")
        trained[name] = model

    return trained

# STEP 6: Evaluate Models
def evaluate_models(trained_models: dict, X_test_s, y_test,
                    X_train_s, y_train) -> dict:
    print_header(6, "Evaluating Models")

    results = {}
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_STATE)

    for name, model in trained_models.items():
        y_pred    = model.predict(X_test_s)
        classes   = list(model.classes_)        
        phish_idx = classes.index(-1)
        legit_idx = classes.index( 1)
        y_proba_phish = model.predict_proba(X_test_s)[:, phish_idx]  # used in predict()
        y_proba       = model.predict_proba(X_test_s)[:, legit_idx]  # used for ROC-AUC

        acc     = accuracy_score(y_test, y_pred)
        prec    = precision_score(y_test, y_pred, pos_label=-1, zero_division=0)
        rec     = recall_score(y_test, y_pred,    pos_label=-1, zero_division=0)
        f1      = f1_score(y_test, y_pred,        pos_label=-1, zero_division=0)
        auc     = roc_auc_score(y_test, y_proba)
        cv_sc   = cross_val_score(model, X_train_s, y_train,
                                  cv=cv, scoring="accuracy", n_jobs=-1)

        results[name] = {
            "accuracy" : acc,
            "precision": prec,
            "recall"   : rec,
            "f1"       : f1,
            "roc_auc"  : auc,
            "cv_mean"  : float(cv_sc.mean()),
            "cv_std"   : float(cv_sc.std()),
            "y_pred"   : y_pred,
            "y_proba"  : y_proba_phish,   
            "model"    : model,
        }

        print(f"\n  ╔══ {name} {'═'*(40-len(name))}╗")
        print(f"  ║  Accuracy       : {acc:.4f}  ({acc*100:.2f}%)")
        print(f"  ║  Precision      : {prec:.4f}")
        print(f"  ║  Recall         : {rec:.4f}")
        print(f"  ║  F1-Score       : {f1:.4f}")
        print(f"  ║  ROC-AUC        : {auc:.4f}")
        print(f"  ║  CV Accuracy    : {cv_sc.mean():.4f} ± {cv_sc.std():.4f}")
        print(f"  ╚{'═'*44}╝")

        print(f"\n  Classification Report — {name}:")
        print(classification_report(
            y_test, y_pred,
            target_names=["Phishing (-1)", "Legitimate (1)"],
            zero_division=0
        ))

    return results


# STEP 7: Select Best Model
def select_best(results: dict):
    print_header(7, "Selecting Best Model (by ROC-AUC)")

    # ROC-AUC is more reliable than accuracy for classification problems
    best_name = max(results, key=lambda n: results[n]["roc_auc"])
    best      = results[best_name]

    for name in results:
        marker = "  ← WINNER" if name == best_name else ""
        print(f"  {name:<25} ROC-AUC={results[name]['roc_auc']:.4f}  "
              f"Accuracy={results[name]['accuracy']*100:.2f}%{marker}")

    return best_name, best["model"]


# STEP 8: Save Charts
def save_charts(results: dict, y_test):
    print_header(8, "Saving Comparison Charts")

    os.makedirs(MODELS_DIR, exist_ok=True)
    names   = list(results.keys())
    colors  = ["#796B01", "#02264B"]

    # ── Bar chart: metric comparison 
    metrics = ["accuracy", "precision", "recall", "f1", "roc_auc"]
    labels  = ["Accuracy", "Precision", "Recall", "F1-Score", "ROC-AUC"]

    fig, ax = plt.subplots(figsize=(10, 5))
    x = np.arange(len(metrics))
    w = 0.30

    for i, (name, color) in enumerate(zip(names, colors)):
        vals = [results[name][m] for m in metrics]
        bars = ax.bar(x + i * w, vals, w, label=name, color=color, alpha=0.87)
        for bar, val in zip(bars, vals):
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 0.005,
                f"{val:.3f}", ha="center", va="bottom", fontsize=8.5
            )

    ax.set_xticks(x + w / 2)
    ax.set_xticklabels(labels, fontsize=11)
    ax.set_ylim(0, 1.12)
    ax.set_ylabel("Score", fontsize=11)
    ax.set_title("Model Performance Comparison: Logistic Regression vs Random Forest",
                 fontsize=12, fontweight="bold", pad=14)
    ax.legend(fontsize=10)
    ax.grid(axis="y", alpha=0.3)
    plt.tight_layout()

    chart_path = os.path.join(MODELS_DIR, "model_comparison.png")
    plt.savefig(chart_path, dpi=150)
    plt.close()
    print(f"  Saved: {chart_path}")

    # Confusion matrices
    fig, axes = plt.subplots(1, 2, figsize=(13, 5))
    fig.suptitle("Confusion Matrices", fontsize=13, fontweight="bold", y=1.01)

    for ax, name, color in zip(axes, names, colors):
        cm = confusion_matrix(y_test, results[name]["y_pred"], labels=[-1, 1])
        sns.heatmap(
            cm, annot=True, fmt="d", cmap="Blues", ax=ax,
            xticklabels=["Phishing", "Legitimate"],
            yticklabels=["Phishing", "Legitimate"],
            annot_kws={"size": 14}
        )
        ax.set_xlabel("Predicted Label", fontsize=11)
        ax.set_ylabel("True Label",      fontsize=11)
        ax.set_title(name, fontsize=11, fontweight="bold")

    plt.tight_layout()
    cm_path = os.path.join(MODELS_DIR, "confusion_matrices.png")
    plt.savefig(cm_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  Saved: {cm_path}")


# MAIN
def main():
    print("\n" + "═"*60)
    print("  PHISHING DETECTION SYSTEM — TRAINING PIPELINE")
    print("═"*60)

    df                              = load_data()
    X, y                            = preprocess(df)
    X_train, X_test, y_train, y_test= split_data(X, y)
    X_train_s, X_test_s, scaler     = scale_features(X_train, X_test)
    trained_models                  = train_models(X_train_s, y_train)
    results                         = evaluate_models(trained_models, X_test_s, y_test,
                                                      X_train_s, y_train)
    best_name, best_model           = select_best(results)
    save_charts(results, y_test)

    # Build metadata for the Streamlit app to display
    metadata = {
        "best_model_name" : best_name,
        "feature_columns" : FEATURE_COLUMNS,
        "metrics": {
            name: {
                "accuracy" : round(r["accuracy"],  4),
                "precision": round(r["precision"], 4),
                "recall"   : round(r["recall"],    4),
                "f1"       : round(r["f1"],        4),
                "roc_auc"  : round(r["roc_auc"],   4),
                "cv_mean"  : round(r["cv_mean"],   4),
                "cv_std"   : round(r["cv_std"],    4),
            }
            for name, r in results.items()
        }
    }

    print_header(9, "Saving Model to Disk")
    save_model(best_model, scaler, metadata)

    print("\n" + "═"*60)
    print(f"  Training Complete!")
    print(f"  Best Model  : {best_name}")
    print(f"  Accuracy    : {results[best_name]['accuracy']*100:.2f}%")
    print(f"  ROC-AUC     : {results[best_name]['roc_auc']:.4f}")
    print(f"\n  Now run:  streamlit run app.py")
    print("═"*60 + "\n")


if __name__ == "__main__":
    main()
