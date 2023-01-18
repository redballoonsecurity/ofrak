#include <stddef.h>   // size_t, NULL
#include <inttypes.h> // uint8_t, uint32_t
#include <math.h>     // floor, log2
// Required to prevent exception with Python >= 3.10
#define PY_SSIZE_T_CLEAN
#include <Python.h>

#define HISTOGRAM_SIZE 256
#define MAX_BRIGHTNESS_FLOAT 255.0
#define LOGGING_CHUNKS 10

/***
 * Use a Python callback to log the current percent completion of the calculation
 */
void log_percent(int percent, void* py_callback){
    PyObject *args = Py_BuildValue("(i)", percent);
    PyObject *result = PyEval_CallObject(py_callback, args);
    Py_XDECREF(result);
    Py_DECREF(args);
}

/***
 * Calculate the Shannon entropy of a distribution of size `window_size` sampled from a sliding
 * window over `data`. The results of each calculation are stored in `result`.
 */
int entropy(uint8_t *data, size_t data_len, uint8_t *result, size_t window_size,
            void* py_log_callback)
{
    if (data == NULL || result == NULL || window_size > data_len || data_len == 0 ||
        window_size == 0) {
        return -1;
    }

    // Initialize and populate histogram and log probability list
    double unscaled_entropy = 0.0;
    double log_window_size = log2((double)window_size);
    double log_probabilities[HISTOGRAM_SIZE];
    uint32_t histogram[HISTOGRAM_SIZE] = {0};

    for (size_t i = 0; i < window_size; i++) {
        histogram[data[i]]++;
    }
    for (size_t i = 0; i < HISTOGRAM_SIZE; i++) {
        double probability = (double)histogram[i] / window_size;
        if (probability != 0.0) {
            log_probabilities[i] = probability * log2(probability);
        } else {
            log_probabilities[i] = 0.0;
        }
        unscaled_entropy += log_probabilities[i];
    }

    // Loop over the data in chunks for logging purposes
    size_t chunk_size = data_len / LOGGING_CHUNKS;
    size_t i = window_size;
    for (size_t chunk = 0; chunk < LOGGING_CHUNKS + 2; chunk++) {
        size_t max_i = chunk * chunk_size;
        // Account for rounding when dividing data_len / LOGGING_CHUNKS by going one chunk too far
        // and making sure i is never more than data_len
        if (max_i > data_len) {
            max_i = data_len;
        }
        for (; i < max_i; i++) {
            // Record the entropy for the latest window
            result[i - window_size] =
                (uint8_t)floor(MAX_BRIGHTNESS_FLOAT * -(unscaled_entropy / log_window_size));

            // There is a byte that is removed from the sliding window as it advances. Remove it
            // from the probability distribution.
            uint8_t next_byte = data[i];
            uint8_t removed_byte = data[i - window_size];

            // Don't recalculate adjustments if they would not change any values
            if (next_byte == removed_byte) {
                continue;
            }

            // Adjust the histogram based on the bytes added to and removed from the distributions
            histogram[removed_byte]--;
            double new_prob = (double)histogram[removed_byte] / window_size;
            double old_log_prob = log_probabilities[removed_byte];
            if (new_prob != 0.0) {
                log_probabilities[removed_byte] = new_prob * log2(new_prob);
            } else {
                log_probabilities[removed_byte] = 0.0;
            }
            unscaled_entropy = unscaled_entropy - old_log_prob + log_probabilities[removed_byte];
            if (unscaled_entropy > 0.0) {
                // Adjust for floating point error
                unscaled_entropy = 0.0;
            }

            histogram[next_byte]++;
            new_prob = (double)histogram[next_byte] / window_size;
            old_log_prob = log_probabilities[next_byte];
            if (new_prob != 0.0) {
                log_probabilities[next_byte] = new_prob * log2(new_prob);
            } else {
                log_probabilities[next_byte] = 0.0;
            }
            unscaled_entropy = unscaled_entropy - old_log_prob + log_probabilities[next_byte];
            if (unscaled_entropy > 0.0) {
                // Adjust for floating point error
                unscaled_entropy = 0.0;
            }
        }

        log_percent((i * 100) / data_len, py_log_callback);
    }

    return 0;
}


PyObject* entropy_wrapper(PyObject* _, PyObject* args){
    Py_buffer data_buffer;
    size_t window_size;
    PyObject* py_log_percent;

    if (!PyArg_ParseTuple(args, "y*nO", &data_buffer, &window_size, &py_log_percent)){
        PyErr_SetString(PyExc_RuntimeError, "Failed to parse arguments to entropy_wrapper!");
        return NULL;
    }

    if (data_buffer.len <= window_size){
        PyBuffer_Release(&data_buffer);
         // return b""
         // we just need a definitely non-NULL pointer to pass to Py_BuildValue
         // &window_size works fine (no data is read from it)
        return Py_BuildValue("y#", &window_size, 0);
    }

    uint8_t *data = data_buffer.buf;
    size_t result_size = data_buffer.len - window_size;
    uint8_t *result = (uint8_t*) calloc(result_size, sizeof(uint8_t));

    // Actual entropy calculation
    entropy(data, data_buffer.len, result, window_size, py_log_percent);

    PyObject* result_object = Py_BuildValue("y#", result, result_size);

    // Clean up memory
    PyBuffer_Release(&data_buffer);
    free(result);

    return result_object;
}


// Functions defined in this module
static PyMethodDef methods[] = {
    {
        "entropy_c",
        entropy_wrapper,
        METH_VARARGS,
        "Calculate the Shannon entropy of a distribution of size `window_size` sampled from a sliding window over `data`. The results of each calculation are stored in `result`."
    },
    {NULL, NULL, 0, NULL}
};


// Module definition
static struct PyModuleDef entropy_definition = {
    PyModuleDef_HEAD_INIT,
    "entropy_c",
    "A Python module that calculates Shannon entropy",
    -1,
    methods,
};

PyObject* PyInit_entropy_c(void) {
    Py_Initialize();
    return PyModule_Create(&entropy_definition);
}
