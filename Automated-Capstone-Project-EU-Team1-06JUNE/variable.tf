variable "vpc_cidr" {
  default = "10.0.0.0/16"
}

variable "cidr_pub_sub1" {
  default = "10.0.1.0/24"
}

variable "cidr_pub_sub2" {
  default = "10.0.2.0/24"
}

variable "cidr_prv_sub1" {
  default = "10.0.3.0/24"
}

variable "cidr_prv_sub2" {
  default = "10.0.4.0/24"
}

variable "rtb_pub_ciderblock" {
  default     = "0.0.0.0/0"
  description = "cider block for the public rtb"
}
variable "rtb_prv_ciderblock" {
  default     = "0.0.0.0/0"
  description = "cider block for the private rtb"

}
/* variable "db_password" {
  default     = "Set10Admin"
  description = "this is the password for RDS"
} */

variable "ami_id" {
  default     = "ami-035c5dc086849b5de"
  description = "this is our ami from eu-west-2"
}


variable "path-to-publickey" {
  default     = "~/Keypairs/pacaad.pub"
  description = "this is path to the keypair in our local machine"
}