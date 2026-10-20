package com.phishguard.ml;

import weka.classifiers.evaluation.Evaluation;
import weka.classifiers.trees.J48;
import weka.core.Instances;
import weka.core.SerializationHelper;

import java.io.File;
import java.util.Random;

/**
 * TrainModel (standalone)
 * ========================
 * Run this ONCE (or whenever you change the dataset) to:
 *   1. Load the phishing dataset (ARFF or CSV) from resources/dataset
 *   2. Train a J48 Decision Tree classifier (easy to explain in a viva)
 *   3. Evaluate it (accuracy, precision, recall, F1, confusion matrix)
 *   4. Save the trained model to resources/dataset/phishguard.model
 *
 * How to run:
 *   mvn -q compile exec:java -Dexec.mainClass=com.phishguard.ml.TrainModel
 * or simply run main() from your IDE.
 *
 * Dataset download instructions are in README.md. The expected file is:
 *   src/main/resources/dataset/training.arff  (or training.csv)
 */
public class TrainModel {

    // Change these to point at your dataset / output model.
    private static final String DATASET_PATH =
            "src/main/resources/dataset/training.arff";
    private static final String MODEL_PATH =
            "src/main/resources/dataset/phishguard.model";

    public static void main(String[] args) {
        try {
            System.out.println("========================================");
            System.out.println(" PhishGuard - Model Training");
            System.out.println("========================================");

            // 1. Load dataset
            System.out.println("[1/4] Loading dataset: " + DATASET_PATH);
            Instances data = WekaUtils.loadDataset(DATASET_PATH);
            data.setClassIndex(data.numAttributes() - 1);
            System.out.println("     Loaded " + data.numInstances() + " instances, "
                    + data.numAttributes() + " attributes.");

            // 2. Train classifier (J48 Decision Tree)
            System.out.println("[2/4] Training J48 classifier...");
            J48 classifier = new J48();
            classifier.setOptions(new String[]{"-C", "0.25", "-M", "2"}); // confidence, min instances
            classifier.buildClassifier(data);

            // 3. Evaluate (10-fold cross-validation)
            System.out.println("[3/4] Evaluating (10-fold CV)...");
            Evaluation eval = new Evaluation(data);
            eval.crossValidateModel(classifier, data, 10, new Random(1));

            System.out.println("\n--- Evaluation Results ---");
            System.out.printf("Accuracy : %.2f%%\n", eval.pctCorrect());
            System.out.printf("Precision: %.2f%%\n", eval.precision(1) * 100);
            System.out.printf("Recall   : %.2f%%\n", eval.recall(1) * 100);
            System.out.printf("F1-Score : %.2f%%\n", eval.fMeasure(1) * 100);
            System.out.println("\nConfusion Matrix (rows=true, cols=predicted):");
            System.out.println(eval.toMatrixString());

            // 4. Save model to disk
            System.out.println("[4/4] Saving model to: " + MODEL_PATH);
            File out = new File(MODEL_PATH);
            out.getParentFile().mkdirs();
            SerializationHelper.write(MODEL_PATH, classifier);
            System.out.println("Done. Model saved successfully.");

        } catch (Exception e) {
            System.err.println("Training failed: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
