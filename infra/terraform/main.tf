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

# Variables
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

variable "vpc_cidr" {
  description = "VPC CIDR block"
  default     = "10.0.0.0/16"
}

# VPC
resource "aws_vpc" "angel_vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${var.project_name}-vpc"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "angel_igw" {
  vpc_id = aws_vpc.angel_vpc.id

  tags = {
    Name = "${var.project_name}-igw"
  }
}

# Public Subnet
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.angel_vpc.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, 1)
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.project_name}-public"
  }
}

# Private Subnet
resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.angel_vpc.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, 2)
  availability_zone = "${var.aws_region}a"

  tags = {
    Name = "${var.project_name}-private"
  }
}

# Security Group
resource "aws_security_group" "angel_sg" {
  name        = "${var.project_name}-sg"
  description = "Security group for ANGEL platform"
  vpc_id      = aws_vpc.angel_vpc.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 8080
    to_port     = 8080
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

  tags = {
    Name = "${var.project_name}-sg"
  }
}

# EC2 Instance
resource "aws_instance" "angel_server" {
  ami                    = "ami-0c55b159cbfafe1f0"
  instance_type          = "t3.medium"
  key_name               = aws_key_pair.angel_key.key_name
  vpc_security_group_ids = [aws_security_group.angel_sg.id]
  subnet_id              = aws_subnet.public.id

  root_block_device {
    volume_size = 50
    volume_type = "gp3"
  }

  tags = {
    Name = "${var.project_name}-server"
  }
}

# Key Pair
resource "aws_key_pair" "angel_key" {
  key_name   = "${var.project_name}-key"
  public_key = file("~/.ssh/id_rsa.pub")
}

# Elastic IP
resource "aws_eip" "angel_eip" {
  instance = aws_instance.angel_server.id
  domain   = "vpc"

  tags = {
    Name = "${var.project_name}-eip"
  }
}

# Outputs
output "server_public_ip" {
  value = aws_eip.angel_eip.public_ip
}

output "server_private_ip" {
  value = aws_instance.angel_server.private_ip
}

output "vpc_id" {
  value = aws_vpc.angel_vpc.id
}
