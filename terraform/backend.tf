# Architect: Lanre Oluokun | Implementation: AI-assisted
# License: MIT

# State lives in GCS, not on a laptop. A local backend means a fresh runner
# starts with empty state and an apply tries to create the 46 resources that
# already exist, which is why deploy.yml could never have worked regardless of
# which secrets were set.
#
# The bucket is created out of band rather than by this configuration: a
# backend cannot be stored in the state it holds. It is versioned (so a
# corrupt or truncated write is recoverable), has public access prevention
# enforced, uses uniform bucket-level access, and is encrypted with the same
# CMEK key as the rest of the project.
#
#   gcloud storage buckets create gs://securevault-demo-tfstate \
#     --project=securevault-demo --location=us-central1 \
#     --uniform-bucket-level-access --public-access-prevention \
#     --default-encryption-key=projects/securevault-demo/locations/us-central1/keyRings/securevault-keyring/cryptoKeys/securevault-key
#   gcloud storage buckets update gs://securevault-demo-tfstate --versioning
terraform {
  backend "gcs" {
    bucket = "securevault-demo-tfstate"
    prefix = "securevault/terraform/state"
  }
}
