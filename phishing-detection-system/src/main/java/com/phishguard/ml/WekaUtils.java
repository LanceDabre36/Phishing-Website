package com.phishguard.ml;

import weka.core.Attribute;
import weka.core.DenseInstance;
import weka.core.Instance;
import weka.core.Instances;
import weka.core.converters.ArffSaver;
import weka.core.converters.CSVLoader;

import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * WekaUtils
 *
 * Shared helpers for building Weka {@link Instances} from our feature maps and
 * for loading the dataset (ARFF or CSV). Keeping this in one place guarantees
 * the training script and the prediction service use the EXACT same attribute
 * structure.
 */
public final class WekaUtils {

    private WekaUtils() {}

    /**
     * Build the empty Instances header with the correct attributes and class.
     * The class attribute is the last one and is nominal (legitimate/phishing).
     */
    public static Instances createHeader(String relationName) {
        ArrayList<Attribute> attrs = new ArrayList<>();

        for (String name : FeatureDefs.FEATURE_NAMES) {
            // All features are numeric (-1, 0, 1 encoded)
            attrs.add(new Attribute(name));
        }

        List<String> classValues = new ArrayList<>();
        classValues.add(FeatureDefs.CLASS_VALUES[0]); // legitimate
        classValues.add(FeatureDefs.CLASS_VALUES[1]); // phishing
        attrs.add(new Attribute(FeatureDefs.CLASS_ATTRIBUTE, classValues));

        Instances data = new Instances(relationName, attrs, 0);
        data.setClassIndex(data.numAttributes() - 1);
        return data;
    }

    /**
     * Convert a feature map (no class) into a Weka Instance using the given
     * header structure. The class value is left missing so the classifier can
     * predict it.
     */
    public static Instance toInstance(Map<String, Integer> features, Instances header) {
        double[] values = new double[header.numAttributes()];
        for (int i = 0; i < FeatureDefs.FEATURE_NAMES.size(); i++) {
            String name = FeatureDefs.FEATURE_NAMES.get(i);
            Integer v = features.get(name);
            values[i] = v == null ? 0.0 : v;
        }
        // class index value left as missing (NaN) for prediction
        values[header.classIndex()] = Double.NaN;

        Instance inst = new DenseInstance(1.0, values);
        inst.setDataset(header);
        return inst;
    }

    /**
     * Load a dataset from ARFF or CSV. CSV is auto-converted: the last column
     * must be the class label (legitimate/phishing).
     */
    public static Instances loadDataset(String path) throws Exception {
        File f = new File(path);
        if (!f.exists()) {
            throw new IllegalArgumentException("Dataset not found: " + path);
        }
        Instances data;
        if (path.toLowerCase().endsWith(".csv")) {
            CSVLoader loader = new CSVLoader();
            loader.setSource(f);
            data = loader.getDataSet();
            // Assume last column is the class
            data.setClassIndex(data.numAttributes() - 1);
        } else {
            data = new Instances(new FileReader(f));
            data.setClassIndex(data.numAttributes() - 1);
        }
        return data;
    }

    /**
     * Save Instances to an ARFF file (used if you want to persist preprocessed data).
     */
    public static void saveArff(Instances data, String path) throws Exception {
        ArffSaver saver = new ArffSaver();
        saver.setInstances(data);
        saver.setFile(new File(path));
        saver.writeBatch();
    }
}
