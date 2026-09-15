terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  description = "AWS region"
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project name"
  default     = "angel"
}

variable "environment" {
  description = "Environment"
  default     = "production"
}

# ============================================
# VPC #1: Recon & Scanning
# ============================================
resource "aws_vpc" "recon_vpc" {
  cidr_block           = "10.1.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags = { Name = "${var.project_name}-recon-vpc" }
}

resource "aws_subnet" "recon_public" {
  vpc_id                  = aws_vpc.recon_vpc.id
  cidr_block              = "10.1.1.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true
  tags = { Name = "${var.project_name}-recon-public" }
}

resource "aws_internet_gateway" "recon_igw" {
  vpc_id = aws_vpc.recon_vpc.id
  tags = { Name = "${var.project_name}-recon-igw" }
}

resource "aws_security_group" "recon_sg" {
  name        = "${var.project_name}-recon-sg"
  description = "Security group for recon VPC"
  vpc_id      = aws_vpc.recon_vpc.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "${var.project_name}-recon-sg" }
}

resource "aws_instance" "recon_server" {
  ami                    = "ami-0c55b159cbfafe1f0"
  instance_type          = "t3.medium"
  key_name               = aws_key_pair.angel_key.key_name
  vpc_security_group_ids = [aws_security_group.recon_sg.id]
  subnet_id              = aws_subnet.recon_public.id
  root_block_device { volume_size = 50; volume_type = "gp3" }
  tags = { Name = "${var.project_name}-recon-server" }
}

resource "aws_eip" "recon_eip" {
  instance = aws_instance.recon_server.id
  domain   = "vpc"
  tags = { Name = "${var.project_name}-recon-eip" }
}

# ============================================
# VPC #2: Phishing & Credential Harvest
# ============================================
resource "aws_vpc" "phishing_vpc" {
  cidr_block           = "10.2.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags = { Name = "${var.project_name}-phishing-vpc" }
}

resource "aws_subnet" "phishing_public" {
  vpc_id                  = aws_vpc.phishing_vpc.id
  cidr_block              = "10.2.1.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true
  tags = { Name = "${var.project_name}-phishing-public" }
}

resource "aws_internet_gateway" "phishing_igw" {
  vpc_id = aws_vpc.phishing_vpc.id
  tags = { Name = "${var.project_name}-phishing-igw" }
}

resource "aws_security_group" "phishing_sg" {
  name        = "${var.project_name}-phishing-sg"
  description = "Security group for phishing VPC"
  vpc_id      = aws_vpc.phishing_vpc.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "${var.project_name}-phishing-sg" }
}

resource "aws_instance" "phishing_server" {
  ami                    = "ami-0c55b159cbfafe1f0"
  instance_type          = "t3.medium"
  key_name               = aws_key_pair.angel_key.key_name
  vpc_security_group_ids = [aws_security_group.phishing_sg.id]
  subnet_id              = aws_subnet.phishing_public.id
  root_block_device { volume_size = 50; volume_type = "gp3" }
  tags = { Name = "${var.project_name}-phishing-server" }
}

resource "aws_eip" "phishing_eip" {
  instance = aws_instance.phishing_server.id
  domain   = "vpc"
  tags = { Name = "${var.project_name}-phishing-eip" }
}

# ============================================
# VPC #3: C2 HTTPS (Teamserver + Listeners)
# ============================================
resource "aws_vpc" "c2https_vpc" {
  cidr_block           = "10.3.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags = { Name = "${var.project_name}-c2https-vpc" }
}

resource "aws_subnet" "c2https_public" {
  vpc_id                  = aws_vpc.c2https_vpc.id
  cidr_block              = "10.3.1.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true
  tags = { Name = "${var.project_name}-c2https-public" }
}

resource "aws_internet_gateway" "c2https_igw" {
  vpc_id = aws_vpc.c2https_vpc.id
  tags = { Name = "${var.project_name}-c2https-igw" }
}

resource "aws_security_group" "c2https_sg" {
  name        = "${var.project_name}-c2https-sg"
  description = "Security group for C2 HTTPS VPC"
  vpc_id      = aws_vpc.c2https_vpc.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 8443
    to_port     = 8443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "${var.project_name}-c2https-sg" }
}

resource "aws_instance" "c2https_server" {
  ami                    = "ami-0c55b159cbfafe1f0"
  instance_type          = "t3.large"
  key_name               = aws_key_pair.angel_key.key_name
  vpc_security_group_ids = [aws_security_group.c2https_sg.id]
  subnet_id              = aws_subnet.c2https_public.id
  root_block_device { volume_size = 100; volume_type = "gp3" }
  tags = { Name = "${var.project_name}-c2https-server" }
}

resource "aws_eip" "c2https_eip" {
  instance = aws_instance.c2https_server.id
  domain   = "vpc"
  tags = { Name = "${var.project_name}-c2https-eip" }
}

# ============================================
# VPC #4: C2 DNS (DNS Listener + Backup)
# ============================================
resource "aws_vpc" "c2dns_vpc" {
  cidr_block           = "10.4.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags = { Name = "${var.project_name}-c2dns-vpc" }
}

resource "aws_subnet" "c2dns_public" {
  vpc_id                  = aws_vpc.c2dns_vpc.id
  cidr_block              = "10.4.1.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true
  tags = { Name = "${var.project_name}-c2dns-public" }
}

resource "aws_internet_gateway" "c2dns_igw" {
  vpc_id = aws_vpc.c2dns_vpc.id
  tags = { Name = "${var.project_name}-c2dns-igw" }
}

resource "aws_security_group" "c2dns_sg" {
  name        = "${var.project_name}-c2dns-sg"
  description = "Security group for C2 DNS VPC"
  vpc_id      = aws_vpc.c2dns_vpc.id

  ingress {
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 53
    to_port     = 53
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "${var.project_name}-c2dns-sg" }
}

resource "aws_instance" "c2dns_server" {
  ami                    = "ami-0c55b159cbfafe1f0"
  instance_type          = "t3.medium"
  key_name               = aws_key_pair.angel_key.key_name
  vpc_security_group_ids = [aws_security_group.c2dns_sg.id]
  subnet_id              = aws_subnet.c2dns_public.id
  root_block_device { volume_size = 50; volume_type = "gp3" }
  tags = { Name = "${var.project_name}-c2dns-server" }
}

resource "aws_eip" "c2dns_eip" {
  instance = aws_instance.c2dns_server.id
  domain   = "vpc"
  tags = { Name = "${var.project_name}-c2dns-eip" }
}

# Key Pair
resource "aws_key_pair" "angel_key" {
  key_name   = "${var.project_name}-key"
  public_key = file("~/.ssh/id_rsa.pub")
}

# VPC Peering
resource "aws_vpc_peering_connection" "recon_to_c2https" {
  vpc_id      = aws_vpc.recon_vpc.id
  peer_vpc_id = aws_vpc.c2https_vpc.id
  auto_accept = true
  tags = { Name = "${var.project_name}-recon-to-c2https" }
}

resource "aws_vpc_peering_connection" "phishing_to_c2https" {
  vpc_id      = aws_vpc.phishing_vpc.id
  peer_vpc_id = aws_vpc.c2https_vpc.id
  auto_accept = true
  tags = { Name = "${var.project_name}-phishing-to-c2https" }
}

# Outputs
output "recon_server_ip" {
  value = aws_eip.recon_eip.public_ip
}

output "phishing_server_ip" {
  value = aws_eip.phishing_eip.public_ip
}

output "c2https_server_ip" {
  value = aws_eip.c2https_eip.public_ip
}

output "c2dns_server_ip" {
  value = aws_eip.c2dns_eip.public_ip
}

output "vpc_ids" {
  value = {
    recon      = aws_vpc.recon_vpc.id
    phishing   = aws_vpc.phishing_vpc.id
    c2https    = aws_vpc.c2https_vpc.id
    c2dns      = aws_vpc.c2dns_vpc.id
  }
}
