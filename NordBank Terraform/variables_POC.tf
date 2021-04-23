#################################################################################################
#    ______    __                     __         __ __ _      ___            
#   / ____/___/ /_  ______ __________/ /___     / //_/(_)__  / (_)___  ____ _
#  / __/ / __  / / / / __ `/ ___/ __  / __ \   / ,<  / / _ \/ / / __ \/ __ `/
# / /___/ /_/ / /_/ / /_/ / /  / /_/ / /_/ /  / /| |/ /  __/ / / / / / /_/ / 
#/_____/\__,_/\__,_/\__,_/_/   \__,_/\____/  /_/ |_/_/\___/_/_/_/ /_/\__, /  
#                                                                   /____/   
#
#Blog: Https://eduardokieling.com
#LinkedIn: https://www.linkedin.com/in/eduardokieling
#Microsoft Azure MVP
#################################################################################################
#
#
#
#
#####################################################################################
#CUSTOM Variables
#####################################################################################
variable company_name {
    description = "Set a Company name (Only Three Letters)"
    default = "NBK"
}
variable infra_location_1 {
    description = "Set a default location"
    default = "switzerlandnorth"
}
variable infra_location_Abreviation_1 {
    description = "Set a default location"
    default = "SWN"
}
variable vpn_sku_1 {
    description = "Set a VPN Type"
    default     = "VpnGw1"
}
variable "vpn_enable_bpg_configuration_1" {
  description = "If set to true, enable bpg with active active configuration"
  default     = "true"
  type        = bool
}

#
#
#
#
#
#
#
#####################################################################################
#DEFAULT Variables
#####################################################################################
variable azure_tenant_id {
}
variable azure_subscription_id {
}
variable azure_client_id {
}
variable azure_client_secret {
}
variable vmuser {
}
variable vmpw {
}
#
##########
#SITE_1
##########
#
variable prd_hub_network_1 {
    default = "172.23.0.0"
}
variable prd_management_network_1 {
    default = "172.23.5.0"
}
variable prd_jumbox_ip_1 {
    default = "172.23.5.100"
}
variable prd_bastion_network_1 {
    default = "172.23.10.32"
}
variable prd_dmz_network_1 {
    default = "172.23.25.0"
}
variable prd_applicationgateway_subnet_1 {
    default = "172.23.11.0"
}
variable prd_firewall_subnet_1 {
    default = "172.23.15.0"
}

variable prd_vpn_network_1 {
    default = "172.23.60.0"
}
variable prd_vpn_pts_network_1 {
    default = "172.23.128.0"
}

variable prd_general_network_1 {
    default = "172.23.64.0"
}
variable qas_general_network_1 {
    default = "172.23.65.0"
}
variable dev_general_network_1 {
    default = "172.23.66.0"
}