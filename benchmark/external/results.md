## Ylemis India-PII

10000 documents, 32030 labelled PII spans of 16 types.

### Detection quality, all of the dataset's types

| Configuration | P (overlap) | R (overlap) | F1 (overlap) | F2 (overlap) | F1 (exact) | Macro-F1 (overlap) | Any-PII F1 | Missed | Over-detected |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| credgate | 98.4 | 50.3 | 66.6 | 55.8 | 66.0 | 61.6 | 66.6 | 15910 | 270 |
| credgate-0.5 | 100.0 | 50.3 | 67.0 | 55.9 | 66.4 | 61.9 | 67.0 | 15910 | 0 |
| credgate-names-0.5 | 100.0 | 51.2 | 67.7 | 56.7 | 67.1 | 62.2 | 67.7 | 15640 | 0 |
| kavach | 100.0 | 35.9 | 52.8 | 41.1 | 52.8 | 43.8 | 52.8 | 20544 | 0 |
| maskflow | 82.5 | 76.8 | 79.6 | 77.9 | 66.0 | 71.8 | 84.5 | 7421 | 5210 |
| presidio | 67.3 | 43.2 | 52.6 | 46.5 | 48.4 | 19.9 | 65.9 | 18188 | 6726 |
| presidio-india | 64.9 | 62.4 | 63.6 | 62.9 | 60.1 | 54.0 | 78.6 | 12050 | 10816 |

### Only the types each tool claims to detect

Gold spans of types a tool has no detector for are left out, so a narrow tool is judged on what it covers.

| Configuration | Types covered | P | R | F1 | F2 |
|---|---:|---:|---:|---:|---:|
| credgate | 11 of 16 | 98.4 | 66.3 | 79.2 | 70.9 |
| credgate-0.5 | 11 of 16 | 100.0 | 66.3 | 79.7 | 71.1 |
| credgate-names-0.5 | 11 of 16 | 100.0 | 67.4 | 80.5 | 72.1 |
| kavach | 7 of 16 | 100.0 | 100.0 | 100.0 | 100.0 |
| maskflow | 12 of 16 | 82.5 | 99.0 | 90.0 | 95.2 |
| presidio | 11 of 16 | 67.3 | 59.5 | 63.2 | 61.0 |
| presidio-india | 11 of 16 | 64.9 | 86.0 | 73.9 | 80.7 |

### Recall by type (overlap)

| Type | Spans | credgate | credgate-0.5 | credgate-names-0.5 | kavach | maskflow | presidio | presidio-india |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| person | 8244 | 1.6 | 1.6 | 4.9 | 0.0 | 98.8 | 90.1 | 90.1 |
| phone | 3650 | 100.0 | 100.0 | 100.0 | 100.0 | 100.0 | 100.0 | 100.0 |
| address | 3649 | 100.0 | 100.0 | 100.0 | 0.0 | 98.4 | 0.0 | 0.0 |
| pan | 2567 | 100.0 | 100.0 | 100.0 | 100.0 | 100.0 | 0.0 | 100.0 |
| account_ref | 2433 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| location | 2433 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 69.3 | 69.3 |
| aadhaar | 1757 | 100.0 | 100.0 | 100.0 | 100.0 | 100.0 | 0.0 | 100.0 |
| organization | 1623 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| upi | 1081 | 100.0 | 100.0 | 100.0 | 100.0 | 100.0 | 0.0 | 0.0 |
| email | 1080 | 100.0 | 100.0 | 100.0 | 100.0 | 100.0 | 100.0 | 100.0 |
| ifsc | 946 | 100.0 | 100.0 | 100.0 | 100.0 | 100.0 | 0.0 | 0.0 |
| medical_id | 676 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| voter_id | 541 | 100.0 | 100.0 | 100.0 | 0.0 | 100.0 | 0.0 | 100.0 |
| vehicle_reg | 540 | 0.0 | 0.0 | 0.0 | 0.0 | 100.0 | 0.0 | 100.0 |
| gstin | 405 | 100.0 | 100.0 | 100.0 | 100.0 | 100.0 | 0.0 | 100.0 |
| passport | 405 | 76.3 | 76.3 | 76.3 | 0.0 | 76.3 | 0.0 | 81.0 |

### Precision by type (overlap; '-' = the tool reported none)

| Type | credgate | credgate-0.5 | credgate-names-0.5 | kavach | maskflow | presidio | presidio-india |
|---|---:|---:|---:|---:|---:|---:|---:|
| person | 100.0 | 100.0 | 100.0 | - | 70.4 | 82.1 | 82.1 |
| phone | 93.1 | 100.0 | 100.0 | 100.0 | 100.0 | 88.4 | 88.8 |
| address | 100.0 | 100.0 | 100.0 | - | 66.8 | - | - |
| pan | 100.0 | 100.0 | 100.0 | 100.0 | 100.0 | - | 38.5 |
| account_ref | - | - | - | - | - | - | - |
| location | - | - | - | - | - | 26.7 | 26.7 |
| aadhaar | 100.0 | 100.0 | 100.0 | 100.0 | 100.0 | - | 100.0 |
| organization | - | - | - | - | - | - | - |
| upi | 100.0 | 100.0 | 100.0 | 100.0 | 100.0 | - | - |
| email | 100.0 | 100.0 | 100.0 | 100.0 | 100.0 | 100.0 | 100.0 |
| ifsc | 100.0 | 100.0 | 100.0 | 100.0 | 100.0 | - | - |
| medical_id | - | - | - | - | - | - | - |
| voter_id | 100.0 | 100.0 | 100.0 | - | 100.0 | - | 100.0 |
| vehicle_reg | - | - | - | - | 100.0 | - | 100.0 |
| gstin | 100.0 | 100.0 | 100.0 | 100.0 | 100.0 | - | 100.0 |
| passport | 100.0 | 100.0 | 100.0 | - | 100.0 | - | 100.0 |

### False positives on PII-free documents

Share of documents with no PII on which the tool reported anything of the dataset's types.

| Configuration | Benign (810) | Hard negatives (946) |
|---|---:|---:|
| credgate | 0.0 | 28.5 |
| credgate-0.5 | 0.0 | 0.0 |
| credgate-names-0.5 | 0.0 | 0.0 |
| kavach | 0.0 | 0.0 |
| maskflow | 16.7 | 0.0 |
| presidio | 50.0 | 28.5 |
| presidio-india | 50.0 | 71.4 |

### Speed and resources

A fixed sample of 2,000 documents, run three times; the median of the three runs. One process, one run at a time, after 20 warm-up documents; model loading timed separately.

| Configuration | Version | p50 ms | p95 ms | Docs/s | MB/s | CPU use | Peak memory MB | Load s |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| credgate | 0.9.0 | 0.35 | 0.59 | 2639 | 0.327 | 98.8% | 32 | 0.17 |
| credgate-0.5 | 0.9.0 | 0.36 | 0.61 | 2544 | 0.315 | 98.8% | 32 | 0.17 |
| credgate-names-0.5 | 0.9.0 | 0.45 | 0.75 | 2074 | 0.257 | 98.8% | 33 | 0.45 |
| kavach | 0.2.0 | 0.13 | 0.21 | 7436 | 0.922 | 99.8% | 18 | 0.13 |
| maskflow | 0.9.2 | 8.64 | 14.41 | 109 | 0.013 | 99.7% | 174 | 0.24 |
| presidio | 2.2.366 | 8.15 | 12.41 | 114 | 0.014 | 99.2% | 750 | 4.48 |
| presidio-india | 2.2.366 | 8.04 | 10.84 | 120 | 0.015 | 99.8% | 749 | 3.89 |

### Predictions set aside (types this dataset does not label)

- maskflow: PIN_CODE 2004
- presidio: US_DRIVER_LICENSE 5271, DATE_TIME 4018, URL 1838, IP_ADDRESS 405, NRP 302, US_BANK_NUMBER 270, MEDICAL_LICENSE 81
- presidio-india: US_DRIVER_LICENSE 5271, DATE_TIME 4018, URL 1838, IP_ADDRESS 405, NRP 302, US_BANK_NUMBER 270, MEDICAL_LICENSE 81

## IndiaPII-Bench v1.0

2000 documents, 12065 labelled PII spans of 17 types.

### Detection quality, all of the dataset's types

| Configuration | P (overlap) | R (overlap) | F1 (overlap) | F2 (overlap) | F1 (exact) | Macro-F1 (overlap) | Any-PII F1 | Missed | Over-detected |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| credgate | 98.6 | 92.9 | 95.6 | 94.0 | 95.6 | 92.4 | 95.6 | 859 | 163 |
| credgate-0.5 | 99.1 | 92.9 | 95.9 | 94.1 | 95.9 | 92.6 | 95.9 | 859 | 102 |
| credgate-names-0.5 | 99.1 | 92.9 | 95.9 | 94.1 | 95.9 | 92.6 | 95.9 | 859 | 105 |
| kavach | 98.8 | 53.2 | 69.2 | 58.7 | 69.2 | 40.8 | 69.8 | 5641 | 78 |
| maskflow | 63.2 | 98.5 | 77.0 | 88.6 | 63.5 | 92.9 | 77.4 | 177 | 6923 |
| presidio | 38.4 | 33.3 | 35.6 | 34.2 | 33.8 | 10.1 | 47.5 | 8052 | 6446 |
| presidio-india | 38.0 | 50.9 | 43.6 | 47.7 | 42.1 | 38.1 | 55.8 | 5918 | 10014 |

### Only the types each tool claims to detect

Gold spans of types a tool has no detector for are left out, so a narrow tool is judged on what it covers.

| Configuration | Types covered | P | R | F1 | F2 |
|---|---:|---:|---:|---:|---:|
| credgate | 16 of 17 | 98.6 | 95.1 | 96.8 | 95.8 |
| credgate-0.5 | 16 of 17 | 99.1 | 95.1 | 97.1 | 95.9 |
| credgate-names-0.5 | 16 of 17 | 99.1 | 95.1 | 97.1 | 95.9 |
| kavach | 7 of 17 | 98.8 | 99.2 | 99.0 | 99.2 |
| maskflow | 17 of 17 | 63.2 | 98.5 | 77.0 | 88.6 |
| presidio | 9 of 17 | 38.4 | 55.2 | 45.3 | 50.8 |
| presidio-india | 9 of 17 | 38.0 | 84.6 | 52.5 | 68.0 |

### Recall by type (overlap)

| Type | Spans | credgate | credgate-0.5 | credgate-names-0.5 | kavach | maskflow | presidio | presidio-india |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| person | 2001 | 71.4 | 71.4 | 71.4 | 0.0 | 100.0 | 59.8 | 59.8 |
| phone | 1790 | 100.0 | 100.0 | 100.0 | 100.0 | 100.0 | 100.0 | 100.0 |
| address | 1230 | 100.0 | 100.0 | 100.0 | 0.0 | 100.0 | 0.0 | 0.0 |
| ifsc | 1142 | 100.0 | 100.0 | 100.0 | 100.0 | 100.0 | 0.0 | 0.0 |
| bank_account | 1142 | 100.0 | 100.0 | 100.0 | 96.0 | 87.7 | 89.8 | 89.8 |
| aadhaar | 857 | 100.0 | 100.0 | 100.0 | 100.0 | 100.0 | 0.0 | 100.0 |
| pin_code | 857 | 100.0 | 100.0 | 100.0 | 0.0 | 100.0 | 0.0 | 0.0 |
| pan | 857 | 100.0 | 100.0 | 100.0 | 100.0 | 100.0 | 0.0 | 100.0 |
| upi | 571 | 100.0 | 100.0 | 100.0 | 99.5 | 100.0 | 0.0 | 0.0 |
| abha_number | 286 | 99.7 | 99.7 | 99.7 | 0.0 | 87.4 | 0.0 | 0.0 |
| vehicle_reg | 286 | 0.0 | 0.0 | 0.0 | 0.0 | 100.0 | 0.0 | 30.8 |
| driving_licence | 286 | 100.0 | 100.0 | 100.0 | 0.0 | 100.0 | 0.0 | 0.0 |
| aadhaar_masked | 285 | 100.0 | 100.0 | 100.0 | 0.0 | 100.0 | 0.0 | 0.0 |
| abha_address | 141 | 100.0 | 100.0 | 100.0 | 0.0 | 100.0 | 0.0 | 0.0 |
| voter_id | 119 | 100.0 | 100.0 | 100.0 | 0.0 | 100.0 | 0.0 | 100.0 |
| gstin | 114 | 100.0 | 100.0 | 100.0 | 100.0 | 100.0 | 0.0 | 98.2 |
| passport | 101 | 100.0 | 100.0 | 100.0 | 0.0 | 100.0 | 0.0 | 100.0 |

### Precision by type (overlap; '-' = the tool reported none)

| Type | credgate | credgate-0.5 | credgate-names-0.5 | kavach | maskflow | presidio | presidio-india |
|---|---:|---:|---:|---:|---:|---:|---:|
| person | 100.0 | 100.0 | 99.8 | - | 35.5 | 26.8 | 26.8 |
| phone | 100.0 | 100.0 | 100.0 | 97.9 | 98.0 | 90.2 | 91.4 |
| address | 100.0 | 100.0 | 100.0 | - | 27.6 | - | - |
| ifsc | 100.0 | 100.0 | 100.0 | 100.0 | 100.0 | - | - |
| bank_account | 100.0 | 100.0 | 100.0 | 100.0 | 100.0 | 25.6 | 25.6 |
| aadhaar | 92.8 | 99.4 | 99.4 | 95.6 | 96.8 | - | 93.4 |
| pin_code | 100.0 | 100.0 | 100.0 | - | 100.0 | - | - |
| pan | 100.0 | 100.0 | 100.0 | 100.0 | 100.0 | - | 19.5 |
| upi | 85.5 | 85.5 | 85.5 | 100.0 | 100.0 | - | - |
| abha_number | 100.0 | 100.0 | 100.0 | - | 100.0 | - | - |
| vehicle_reg | - | - | - | - | 100.0 | - | 97.8 |
| driving_licence | 100.0 | 100.0 | 100.0 | - | 100.0 | - | - |
| aadhaar_masked | 100.0 | 100.0 | 100.0 | - | 100.0 | - | - |
| abha_address | 100.0 | 100.0 | 100.0 | - | 100.0 | - | - |
| voter_id | 100.0 | 100.0 | 100.0 | - | 100.0 | - | 100.0 |
| gstin | 100.0 | 100.0 | 100.0 | 100.0 | 100.0 | - | 100.0 |
| passport | 100.0 | 100.0 | 100.0 | - | 100.0 | - | 100.0 |

### Decoys hit

Share of labelled PII-shaped decoys that a prediction of the dataset's types overlaps.

| Configuration | NON_VERHOEFF_AADHAAR_SHAPED (63) | ORDER_ID_SHAPED (564) | PAN_SHAPED_INVOICE_NO (107) | TIMESTAMP_SHAPED (572) | VPA_SHAPED_EMAIL (97) | All |
|---|---:|---:|---:|---:|---:|---:|
| credgate | 0.0 | 11.7 | 0.0 | 0.0 | 100.0 | 11.6 |
| credgate-0.5 | 0.0 | 0.9 | 0.0 | 0.0 | 100.0 | 7.3 |
| credgate-names-0.5 | 0.0 | 0.9 | 0.0 | 0.0 | 100.0 | 7.3 |
| kavach | 3.2 | 3.2 | 0.0 | 0.0 | 0.0 | 1.4 |
| maskflow | 0.0 | 0.2 | 0.0 | 0.0 | 23.7 | 1.7 |
| presidio | 100.0 | 100.0 | 0.9 | 49.8 | 20.6 | 66.5 |
| presidio-india | 100.0 | 100.0 | 100.0 | 49.8 | 20.6 | 74.1 |

### Speed and resources

A fixed sample of 2,000 documents, run three times; the median of the three runs. One process, one run at a time, after 20 warm-up documents; model loading timed separately.

| Configuration | Version | p50 ms | p95 ms | Docs/s | MB/s | CPU use | Peak memory MB | Load s |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| credgate | 0.9.0 | 0.89 | 1.27 | 1058 | 0.322 | 99.1% | 34 | 0.18 |
| credgate-0.5 | 0.9.0 | 0.89 | 1.33 | 1053 | 0.320 | 99.2% | 34 | 0.17 |
| credgate-names-0.5 | 0.9.0 | 1.09 | 1.53 | 860 | 0.262 | 99.0% | 34 | 0.43 |
| kavach | 0.2.0 | 0.31 | 0.43 | 3047 | 0.927 | 99.6% | 20 | 0.10 |
| maskflow | 0.9.2 | 19.22 | 25.95 | 50 | 0.015 | 99.7% | 174 | 0.23 |
| presidio | 2.2.366 | 15.20 | 25.85 | 57 | 0.018 | 97.6% | 668 | 4.29 |
| presidio-india | 2.2.366 | 14.71 | 23.19 | 63 | 0.019 | 99.0% | 744 | 4.33 |

### Predictions set aside (types this dataset does not label)

- credgate: card 1
- credgate-0.5: card 1
- credgate-names-0.5: card 1
- maskflow: CREDIT_CARD 137
- presidio: US_DRIVER_LICENSE 4928, LOCATION 2952, DATE_TIME 1053, URL 170, NRP 154, UK_NHS 124, US_PASSPORT 116, US_SSN 116
- presidio-india: US_DRIVER_LICENSE 4928, LOCATION 2952, DATE_TIME 1053, URL 170, NRP 154, UK_NHS 124, US_PASSPORT 116, US_SSN 116

## credgate's own corpus (test split)

700 documents, 1320 labelled PII spans of 22 types.

### Detection quality, all of the dataset's types

| Configuration | P (overlap) | R (overlap) | F1 (overlap) | F2 (overlap) | F1 (exact) | Macro-F1 (overlap) | Any-PII F1 | Missed | Over-detected |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| credgate | 92.6 | 97.4 | 94.9 | 96.4 | 94.9 | 96.9 | 96.2 | 34 | 103 |
| credgate-0.5 | 100.0 | 96.1 | 98.0 | 96.9 | 98.0 | 97.5 | 98.0 | 51 | 0 |
| credgate-names-0.5 | 100.0 | 97.4 | 98.7 | 97.9 | 98.7 | 97.6 | 98.7 | 34 | 0 |
| kavach | 96.9 | 40.2 | 56.9 | 45.6 | 56.9 | 34.8 | 57.6 | 789 | 17 |
| maskflow | 70.1 | 72.5 | 71.3 | 72.0 | 65.6 | 64.1 | 75.2 | 363 | 409 |
| presidio | 42.7 | 39.4 | 41.0 | 40.0 | 38.1 | 16.4 | 53.1 | 800 | 698 |
| presidio-india | 41.7 | 56.4 | 47.9 | 52.7 | 45.6 | 34.3 | 60.9 | 575 | 1043 |

### Only the types each tool claims to detect

Gold spans of types a tool has no detector for are left out, so a narrow tool is judged on what it covers.

| Configuration | Types covered | P | R | F1 | F2 |
|---|---:|---:|---:|---:|---:|
| credgate | 22 of 22 | 92.6 | 97.4 | 94.9 | 96.4 |
| credgate-0.5 | 22 of 22 | 100.0 | 96.1 | 98.0 | 96.9 |
| credgate-names-0.5 | 22 of 22 | 100.0 | 97.4 | 98.7 | 97.9 |
| kavach | 8 of 22 | 96.9 | 93.8 | 95.3 | 94.4 |
| maskflow | 17 of 22 | 70.1 | 85.8 | 77.1 | 82.1 |
| presidio | 10 of 22 | 42.7 | 63.0 | 50.9 | 57.5 |
| presidio-india | 10 of 22 | 41.7 | 90.2 | 57.0 | 73.2 |

### Recall by type (overlap)

| Type | Spans | credgate | credgate-0.5 | credgate-names-0.5 | kavach | maskflow | presidio | presidio-india |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| person | 241 | 92.9 | 92.9 | 100.0 | 0.0 | 100.0 | 75.5 | 75.5 |
| phone | 155 | 100.0 | 100.0 | 100.0 | 100.0 | 67.1 | 100.0 | 100.0 |
| aadhaar | 86 | 100.0 | 100.0 | 100.0 | 80.2 | 80.2 | 0.0 | 80.2 |
| pan | 69 | 100.0 | 100.0 | 100.0 | 100.0 | 75.4 | 0.0 | 100.0 |
| abha_number | 68 | 100.0 | 100.0 | 100.0 | 0.0 | 83.8 | 0.0 | 0.0 |
| bank_account | 68 | 100.0 | 100.0 | 100.0 | 73.5 | 50.0 | 92.6 | 92.6 |
| card | 68 | 100.0 | 100.0 | 100.0 | 0.0 | 100.0 | 100.0 | 100.0 |
| email | 52 | 100.0 | 100.0 | 100.0 | 100.0 | 100.0 | 100.0 | 100.0 |
| address | 52 | 100.0 | 100.0 | 100.0 | 0.0 | 100.0 | 0.0 | 0.0 |
| ckyc | 51 | 66.7 | 66.7 | 66.7 | 0.0 | 0.0 | 0.0 | 0.0 |
| ifsc | 51 | 100.0 | 100.0 | 100.0 | 100.0 | 66.7 | 0.0 | 0.0 |
| nrega_job_card | 51 | 100.0 | 100.0 | 100.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| upi | 51 | 100.0 | 100.0 | 100.0 | 100.0 | 100.0 | 0.0 | 0.0 |
| voter_id | 35 | 100.0 | 51.4 | 51.4 | 0.0 | 100.0 | 0.0 | 100.0 |
| gstin | 34 | 100.0 | 100.0 | 100.0 | 100.0 | 100.0 | 0.0 | 100.0 |
| card_cvv | 34 | 100.0 | 100.0 | 100.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| card_expiry | 34 | 100.0 | 100.0 | 100.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| abha_address | 34 | 100.0 | 100.0 | 100.0 | 0.0 | 100.0 | 0.0 | 0.0 |
| ration_card | 34 | 100.0 | 100.0 | 100.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| passport | 18 | 100.0 | 100.0 | 100.0 | 0.0 | 100.0 | 0.0 | 100.0 |
| driving_licence | 17 | 100.0 | 100.0 | 100.0 | 0.0 | 94.1 | 0.0 | 0.0 |
| pin_code | 17 | 100.0 | 100.0 | 100.0 | 0.0 | 35.3 | 0.0 | 0.0 |

### Precision by type (overlap; '-' = the tool reported none)

| Type | credgate | credgate-0.5 | credgate-names-0.5 | kavach | maskflow | presidio | presidio-india |
|---|---:|---:|---:|---:|---:|---:|---:|
| person | 100.0 | 100.0 | 100.0 | - | 50.6 | 50.3 | 50.3 |
| phone | 96.9 | 100.0 | 100.0 | 98.7 | 100.0 | 68.6 | 73.5 |
| aadhaar | 51.5 | 100.0 | 100.0 | 82.1 | 44.2 | - | 43.7 |
| pan | 100.0 | 100.0 | 100.0 | 100.0 | 100.0 | - | 20.3 |
| abha_number | 80.0 | 100.0 | 100.0 | - | 100.0 | - | - |
| bank_account | 100.0 | 100.0 | 100.0 | 100.0 | 100.0 | 12.4 | 12.4 |
| card | 100.0 | 100.0 | 100.0 | - | 78.2 | 95.8 | 95.8 |
| email | 100.0 | 100.0 | 100.0 | 100.0 | 100.0 | 100.0 | 100.0 |
| address | 100.0 | 100.0 | 100.0 | - | 60.5 | - | - |
| ckyc | 100.0 | 100.0 | 100.0 | - | - | - | - |
| ifsc | 100.0 | 100.0 | 100.0 | 100.0 | 100.0 | - | - |
| nrega_job_card | 100.0 | 100.0 | 100.0 | - | - | - | - |
| upi | 100.0 | 100.0 | 100.0 | 100.0 | 100.0 | - | - |
| voter_id | 100.0 | 100.0 | 100.0 | - | 100.0 | - | 100.0 |
| gstin | 100.0 | 100.0 | 100.0 | 100.0 | 100.0 | - | 100.0 |
| card_cvv | 100.0 | 100.0 | 100.0 | - | - | - | - |
| card_expiry | 100.0 | 100.0 | 100.0 | - | - | - | - |
| abha_address | 100.0 | 100.0 | 100.0 | - | 100.0 | - | - |
| ration_card | 100.0 | 100.0 | 100.0 | - | - | - | - |
| passport | 100.0 | 100.0 | 100.0 | - | 100.0 | - | 100.0 |
| driving_licence | 100.0 | 100.0 | 100.0 | - | 100.0 | - | - |
| pin_code | 100.0 | 100.0 | 100.0 | - | 15.0 | - | - |

### False positives on PII-free documents

Share of the 136 documents with no PII on which the tool reported anything of the corpus's types.

| Configuration | Documents with a false positive |
|---|---:|
| credgate | 34.6 |
| credgate-0.5 | 0.0 |
| credgate-names-0.5 | 0.0 |
| kavach | 0.0 |
| maskflow | 42.6 |
| presidio | 75.0 |
| presidio-india | 75.0 |

### Speed and resources

A fixed sample of 2,000 documents, run three times; the median of the three runs. One process, one run at a time, after 20 warm-up documents; model loading timed separately.

| Configuration | Version | p50 ms | p95 ms | Docs/s | MB/s | CPU use | Peak memory MB | Load s |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| credgate | 0.9.0 | 0.32 | 0.53 | 2712 | 0.221 | 99.0% | 31 | 0.17 |
| credgate-0.5 | 0.9.0 | 0.32 | 0.51 | 2819 | 0.229 | 98.8% | 31 | 0.16 |
| credgate-names-0.5 | 0.9.0 | 0.37 | 0.61 | 2412 | 0.196 | 98.8% | 32 | 0.46 |
| kavach | 0.2.0 | 0.09 | 0.19 | 8679 | 0.706 | 99.4% | 16 | 0.09 |
| maskflow | 0.9.2 | 7.45 | 11.39 | 129 | 0.011 | 99.1% | 172 | 0.20 |
| presidio | 2.2.366 | 8.48 | 11.67 | 114 | 0.009 | 99.1% | 748 | 3.57 |
| presidio-india | 2.2.366 | 8.21 | 10.82 | 119 | 0.010 | 99.2% | 748 | 3.43 |

### Predictions set aside (types this dataset does not label)

- maskflow: DATE_OF_BIRTH 4
- presidio: US_DRIVER_LICENSE 683, DATE_TIME 325, URL 83, LOCATION 46, US_PASSPORT 10, US_SSN 10, UK_NHS 10, NRP 5
- presidio-india: US_DRIVER_LICENSE 683, DATE_TIME 325, URL 83, LOCATION 46, US_PASSPORT 10, US_SSN 10, UK_NHS 10, NRP 5

