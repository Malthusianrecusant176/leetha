"""Leetha service identification plugin registry.

Auto-discovered plugins that implement the ServiceProbe interface for
active service detection. Each plugin identifies a specific network
service by analyzing protocol handshakes and banner responses.

See :mod:`leetha.probe.discovery` for the auto-discovery mechanism.
"""

from leetha.probe.plugins.acme import ACMEProbePlugin
from leetha.probe.plugins.activemq import ActiveMQProbePlugin
from leetha.probe.plugins.aetitle import AETitleProbePlugin
from leetha.probe.plugins.afp import AFPProbePlugin
from leetha.probe.plugins.airplay import AirPlayProbePlugin
from leetha.probe.plugins.amqp import AMQPProbePlugin
from leetha.probe.plugins.anyconnect import AnyConnectProbePlugin
from leetha.probe.plugins.anydesk import AnyDeskProbePlugin
from leetha.probe.plugins.arangodb import ArangoDBProbePlugin
from leetha.probe.plugins.argocd import ArgoCDProbePlugin
from leetha.probe.plugins.artifactory import ArtifactoryProbePlugin
from leetha.probe.plugins.aruba import ArubaProbePlugin
from leetha.probe.plugins.asterix import ASTERIXProbePlugin
from leetha.probe.plugins.atg import ATGProbePlugin
from leetha.probe.plugins.bacnet import BACnetProbePlugin
from leetha.probe.plugins.beegfs import BeeGFSProbePlugin
from leetha.probe.plugins.bgp import BGPProbePlugin
from leetha.probe.plugins.boundary import BoundaryProbePlugin
from leetha.probe.plugins.calico import CalicoProbePlugin
from leetha.probe.plugins.canopen import CANopenProbePlugin
from leetha.probe.plugins.cas import CASProbePlugin
from leetha.probe.plugins.cassandra import CassandraProbePlugin
from leetha.probe.plugins.ceph import CephProbePlugin
from leetha.probe.plugins.chromadb import ChromaDBProbePlugin
from leetha.probe.plugins.cics import CICSProbePlugin
from leetha.probe.plugins.cifs import CIFSProbePlugin
from leetha.probe.plugins.cilium import CiliumProbePlugin
from leetha.probe.plugins.cisco_smart_install import CiscoSmartInstallProbePlugin
from leetha.probe.plugins.clickhouse import ClickHouseProbePlugin
from leetha.probe.plugins.coap import CoAPProbePlugin
from leetha.probe.plugins.cockpit import CockpitProbePlugin
from leetha.probe.plugins.cockroachdb import CockroachDBProbePlugin
from leetha.probe.plugins.codesys import CodesysProbePlugin
from leetha.probe.plugins.condor import CondorProbePlugin
from leetha.probe.plugins.conjur import ConjurProbePlugin
from leetha.probe.plugins.consul import ConsulProbePlugin
from leetha.probe.plugins.containerd import ContainerdProbePlugin
from leetha.probe.plugins.couchdb import CouchDBProbePlugin
from leetha.probe.plugins.crimsonv3 import CrimsonV3ProbePlugin
from leetha.probe.plugins.dask import DaskProbePlugin
from leetha.probe.plugins.db2 import DB2ProbePlugin
from leetha.probe.plugins.dds import DDSProbePlugin
from leetha.probe.plugins.diameter import DiameterProbePlugin
from leetha.probe.plugins.dicom import DICOMProbePlugin
from leetha.probe.plugins.dlna import DLNAProbePlugin
from leetha.probe.plugins.dnp3 import DNP3ProbePlugin
from leetha.probe.plugins.dns import DNSProbePlugin
from leetha.probe.plugins.docker_api import DockerAPIProbePlugin
from leetha.probe.plugins.docker_registry import DockerRegistryProbePlugin
from leetha.probe.plugins.dovecot import DovecotProbePlugin
from leetha.probe.plugins.drda import DRDAProbePlugin
from leetha.probe.plugins.elasticsearch import ElasticsearchProbePlugin
from leetha.probe.plugins.emby import EmbyProbePlugin
from leetha.probe.plugins.enip import ENIPProbePlugin
from leetha.probe.plugins.envoy_admin import EnvoyAdminProbePlugin
from leetha.probe.plugins.epics import EPICSProbePlugin
from leetha.probe.plugins.etcd import EtcdProbePlugin
from leetha.probe.plugins.ethercat import EtherCATProbePlugin
from leetha.probe.plugins.ff_hse import FFHSEProbePlugin
from leetha.probe.plugins.fhir import FHIRProbePlugin
from leetha.probe.plugins.finger import FingerProbePlugin
from leetha.probe.plugins.fins import FINSProbePlugin
from leetha.probe.plugins.firebird import FirebirdProbePlugin
from leetha.probe.plugins.fission import FissionProbePlugin
from leetha.probe.plugins.fluentd import FluentdProbePlugin
from leetha.probe.plugins.fortigate import FortiGateProbePlugin
from leetha.probe.plugins.fox import FoxProbePlugin
from leetha.probe.plugins.freeipa import FreeIPAProbePlugin
from leetha.probe.plugins.ftp import FTPProbePlugin
from leetha.probe.plugins.ge_srtp import GESRTPProbePlugin
from leetha.probe.plugins.git_proto import GitProtoProbePlugin
from leetha.probe.plugins.gradio_app import GradioProbePlugin
from leetha.probe.plugins.gitlab import GitLabProbePlugin
from leetha.probe.plugins.globalprotect import GlobalProtectProbePlugin
from leetha.probe.plugins.globus import GlobusProbePlugin
from leetha.probe.plugins.glusterfs import GlusterFSProbePlugin
from leetha.probe.plugins.google_cast import GoogleCastProbePlugin
from leetha.probe.plugins.gopher import GopherProbePlugin
from leetha.probe.plugins.gpfs import GPFSProbePlugin
from leetha.probe.plugins.grafana import GrafanaProbePlugin
from leetha.probe.plugins.graphite import GraphiteProbePlugin
from leetha.probe.plugins.graphql import GraphQLProbePlugin
from leetha.probe.plugins.graylog_gelf import GraylogGELFProbePlugin
from leetha.probe.plugins.grpc import GRPCProbePlugin
from leetha.probe.plugins.gtp import GTPProbePlugin
from leetha.probe.plugins.h323 import H323ProbePlugin
from leetha.probe.plugins.hadoop_namenode import HadoopNameNodeProbePlugin
from leetha.probe.plugins.haproxy_stats import HAProxyStatsProbePlugin
from leetha.probe.plugins.harbor import HarborProbePlugin
from leetha.probe.plugins.hartip import HARTIPProbePlugin
from leetha.probe.plugins.hbase import HBaseProbePlugin
from leetha.probe.plugins.hikvision import HikvisionProbePlugin
from leetha.probe.plugins.hl7_mllp import HL7MLLPProbePlugin
from leetha.probe.plugins.hls import HLSProbePlugin
from leetha.probe.plugins.home_assistant import HomeAssistantProbePlugin
from leetha.probe.plugins.homekit import HomeKitProbePlugin
from leetha.probe.plugins.huggingface_tgi import HuggingFaceTGIProbePlugin
from leetha.probe.plugins.http import HTTPProbePlugin
from leetha.probe.plugins.http_proxy import HTTPProxyProbePlugin
from leetha.probe.plugins.hue_bridge import HueBridgeProbePlugin
from leetha.probe.plugins.hyperv import HyperVProbePlugin
from leetha.probe.plugins.iax2 import IAX2ProbePlugin
from leetha.probe.plugins.icecast import IcecastProbePlugin
from leetha.probe.plugins.iec104 import IEC104ProbePlugin
from leetha.probe.plugins.iec61850 import IEC61850ProbePlugin
from leetha.probe.plugins.ike import IKEProbePlugin
from leetha.probe.plugins.imap import IMAPProbePlugin
from leetha.probe.plugins.ims_connect import IMSConnectProbePlugin
from leetha.probe.plugins.influxdb import InfluxDBProbePlugin
from leetha.probe.plugins.iolink import IOLinkProbePlugin
from leetha.probe.plugins.ipfix import IPFIXProbePlugin
from leetha.probe.plugins.ipmi import IPMIProbePlugin
from leetha.probe.plugins.ipp import IPPProbePlugin
from leetha.probe.plugins.irc import IRCProbePlugin
from leetha.probe.plugins.iscsi import ISCSIProbePlugin
from leetha.probe.plugins.jdwp import JDWPProbePlugin
from leetha.probe.plugins.jenkins import JenkinsProbePlugin
from leetha.probe.plugins.jetdirect import JetDirectProbePlugin
from leetha.probe.plugins.jmx import JMXProbePlugin
from leetha.probe.plugins.jreap import JREAPProbePlugin
from leetha.probe.plugins.k3s import K3sProbePlugin
from leetha.probe.plugins.kafka import KafkaProbePlugin
from leetha.probe.plugins.kerberos import KerberosProbePlugin
from leetha.probe.plugins.keycloak import KeycloakProbePlugin
from leetha.probe.plugins.kibana import KibanaProbePlugin
from leetha.probe.plugins.knative import KnativeProbePlugin
from leetha.probe.plugins.knxip import KNXIPProbePlugin
from leetha.probe.plugins.kong import KongProbePlugin
from leetha.probe.plugins.kubernetes_api import KubernetesAPIProbePlugin
from leetha.probe.plugins.l2tp import L2TPProbePlugin
from leetha.probe.plugins.ldap import LDAPProbePlugin
from leetha.probe.plugins.libvirt import LibvirtProbePlugin
from leetha.probe.plugins.link16 import Link16ProbePlugin
from leetha.probe.plugins.litellm import LiteLLMProbePlugin
from leetha.probe.plugins.linkerd import LinkerdProbePlugin
from leetha.probe.plugins.llmnr import LLMNRProbePlugin
from leetha.probe.plugins.lmtp import LMTPProbePlugin
from leetha.probe.plugins.lpd import LPDProbePlugin
from leetha.probe.plugins.lustre import LustreProbePlugin
from leetha.probe.plugins.lwm2m import LwM2MProbePlugin
from leetha.probe.plugins.lxi import LXIProbePlugin
from leetha.probe.plugins.managesieve import ManageSieveProbePlugin
from leetha.probe.plugins.matrix import MatrixProbePlugin
from leetha.probe.plugins.mattermost import MattermostProbePlugin
from leetha.probe.plugins.mdns_probe import MDNSProbePlugin
from leetha.probe.plugins.melsec import MELSECProbePlugin
from leetha.probe.plugins.memcached import MemcachedProbePlugin
from leetha.probe.plugins.mgcp import MGCPProbePlugin
from leetha.probe.plugins.mikrotik import MikroTikProbePlugin
from leetha.probe.plugins.milter import MilterProbePlugin
from leetha.probe.plugins.minio import MinIOProbePlugin
from leetha.probe.plugins.modbus import ModbusProbePlugin
from leetha.probe.plugins.modbus_rtu import ModbusRTUProbePlugin
from leetha.probe.plugins.mongodb import MongoDBProbePlugin
from leetha.probe.plugins.mpd import MPDProbePlugin
from leetha.probe.plugins.mpi import MPIProbePlugin
from leetha.probe.plugins.mq_series import MQSeriesProbePlugin
from leetha.probe.plugins.mqtt import MQTTProbePlugin
from leetha.probe.plugins.mssql import MSSQLProbePlugin
from leetha.probe.plugins.mumble import MumbleProbePlugin
from leetha.probe.plugins.mysql import MySQLProbePlugin
from leetha.probe.plugins.nato_mip import NATOMIPProbePlugin
from leetha.probe.plugins.nats import NATSProbePlugin
from leetha.probe.plugins.ndmp import NDMPProbePlugin
from leetha.probe.plugins.neo4j import Neo4jProbePlugin
from leetha.probe.plugins.netbios import NetBIOSProbePlugin
from leetha.probe.plugins.nexus import NexusProbePlugin
from leetha.probe.plugins.nexus_rm import NexusRMProbePlugin
from leetha.probe.plugins.nfs import NFSProbePlugin
from leetha.probe.plugins.nntp import NNTPProbePlugin
from leetha.probe.plugins.nomad import NomadProbePlugin
from leetha.probe.plugins.nrpe import NRPEProbePlugin
from leetha.probe.plugins.ntlm import NTLMProbePlugin
from leetha.probe.plugins.ntp import NTPProbePlugin
from leetha.probe.plugins.nuclio import NuclioProbePlugin
from leetha.probe.plugins.nutanix import NutanixProbePlugin
from leetha.probe.plugins.nx import NXProbePlugin
from leetha.probe.plugins.oauth2 import OAuth2ProbePlugin
from leetha.probe.plugins.ollama import OllamaProbePlugin
from leetha.probe.plugins.openai_compat import OpenAICompatProbePlugin
from leetha.probe.plugins.onvif import ONVIFProbePlugin
from leetha.probe.plugins.opcda import OPCDAProbePlugin
from leetha.probe.plugins.opcua import OPCUAProbePlugin
from leetha.probe.plugins.openfaas import OpenFaaSProbePlugin
from leetha.probe.plugins.openhab import OpenHABProbePlugin
from leetha.probe.plugins.openshift import OpenShiftProbePlugin
from leetha.probe.plugins.openvpn import OpenVPNProbePlugin
from leetha.probe.plugins.openwhisk import OpenWhiskProbePlugin
from leetha.probe.plugins.openwrt import OpenWrtProbePlugin
from leetha.probe.plugins.oracle_tns import OracleTNSProbePlugin
from leetha.probe.plugins.otlp import OTLPProbePlugin
from leetha.probe.plugins.ovirt import OvirtProbePlugin
from leetha.probe.plugins.pacs import PACSProbePlugin
from leetha.probe.plugins.pbs import PBSProbePlugin
from leetha.probe.plugins.pcom import PCOMProbePlugin
from leetha.probe.plugins.pcworx import PCWorxProbePlugin
from leetha.probe.plugins.perforce import PerforceProbePlugin
from leetha.probe.plugins.pfsense import PfSenseProbePlugin
from leetha.probe.plugins.pgadmin import PgAdminProbePlugin
from leetha.probe.plugins.phpmyadmin import PhpMyAdminProbePlugin
from leetha.probe.plugins.plex import PlexProbePlugin
from leetha.probe.plugins.podman import PodmanProbePlugin
from leetha.probe.plugins.pop3 import POP3ProbePlugin
from leetha.probe.plugins.portainer import PortainerProbePlugin
from leetha.probe.plugins.postgresql import PostgreSQLProbePlugin
from leetha.probe.plugins.pptp import PPTPProbePlugin
from leetha.probe.plugins.proconos import ProConOSProbePlugin
from leetha.probe.plugins.profinet import PROFINETProbePlugin
from leetha.probe.plugins.prometheus import PrometheusProbePlugin
from leetha.probe.plugins.proxmox_ve import ProxmoxVEProbePlugin
from leetha.probe.plugins.pulsar import PulsarProbePlugin
from leetha.probe.plugins.puppet import PuppetProbePlugin
from leetha.probe.plugins.qnap import QNAPProbePlugin
from leetha.probe.plugins.quay import QuayProbePlugin
from leetha.probe.plugins.rabbitmq import RabbitMQProbePlugin
from leetha.probe.plugins.radius import RADIUSProbePlugin
from leetha.probe.plugins.rancher import RancherProbePlugin
from leetha.probe.plugins.ray import RayProbePlugin
from leetha.probe.plugins.rdp import RDPProbePlugin
from leetha.probe.plugins.redcap import REDCapProbePlugin
from leetha.probe.plugins.redis import RedisProbePlugin
from leetha.probe.plugins.rlogin import RloginProbePlugin
from leetha.probe.plugins.rmi import RMIProbePlugin
from leetha.probe.plugins.roku_ecp import RokuECPProbePlugin
from leetha.probe.plugins.rsh import RSHProbePlugin
from leetha.probe.plugins.rspamd import RspamdProbePlugin
from leetha.probe.plugins.rsync import RsyncProbePlugin
from leetha.probe.plugins.rtmp import RTMPProbePlugin
from leetha.probe.plugins.rtsp import RTSPProbePlugin
from leetha.probe.plugins.rtsp_probe import RtspProbePlugin
from leetha.probe.plugins.ruckus import RuckusProbePlugin
from leetha.probe.plugins.s3_compat import S3CompatProbePlugin
from leetha.probe.plugins.s7comm import S7commProbePlugin
from leetha.probe.plugins.salt import SaltProbePlugin
from leetha.probe.plugins.saml import SAMLProbePlugin
from leetha.probe.plugins.sane import SANEProbePlugin
from leetha.probe.plugins.sap_diag import SAPDiagProbePlugin
from leetha.probe.plugins.sap_router import SAPRouterProbePlugin
from leetha.probe.plugins.scpi_raw import SCPIRawProbePlugin
from leetha.probe.plugins.sctp_test import SCTPTestProbePlugin
from leetha.probe.plugins.scylladb import ScyllaDBProbePlugin
from leetha.probe.plugins.sflow import SFlowProbePlugin
from leetha.probe.plugins.sge import SGEProbePlugin
from leetha.probe.plugins.shelly import ShellyProbePlugin
from leetha.probe.plugins.shoutcast import SHOUTcastProbePlugin
from leetha.probe.plugins.sip import SIPProbePlugin
from leetha.probe.plugins.slurm import SlurmProbePlugin
from leetha.probe.plugins.smb import SMBProbePlugin
from leetha.probe.plugins.smpp import SMPPProbePlugin
from leetha.probe.plugins.smtp import SMTPProbePlugin
from leetha.probe.plugins.snmp import SNMPProbePlugin
from leetha.probe.plugins.socks4 import SOCKS4ProbePlugin
from leetha.probe.plugins.socks5 import SOCKS5ProbePlugin
from leetha.probe.plugins.softether import SoftEtherProbePlugin
from leetha.probe.plugins.sonarqube import SonarQubeProbePlugin
from leetha.probe.plugins.sonos import SonosProbePlugin
from leetha.probe.plugins.spark_master import SparkMasterProbePlugin
from leetha.probe.plugins.spiffe import SPIFFEProbePlugin
from leetha.probe.plugins.splunk_hec import SplunkHECProbePlugin
from leetha.probe.plugins.ssdp import SSDPProbePlugin
from leetha.probe.plugins.ssh import SSHProbePlugin
from leetha.probe.plugins.stable_diffusion import StableDiffusionProbePlugin
from leetha.probe.plugins.sstp import SSTPProbePlugin
from leetha.probe.plugins.stanag import STANAG4586ProbePlugin
from leetha.probe.plugins.statsd import StatsDProbePlugin
from leetha.probe.plugins.step_ca import StepCAProbePlugin
from leetha.probe.plugins.stomp import STOMPProbePlugin
from leetha.probe.plugins.stun import STUNProbePlugin
from leetha.probe.plugins.submission import SubmissionProbePlugin
from leetha.probe.plugins.svn import SVNProbePlugin
from leetha.probe.plugins.swift_storage import SwiftStorageProbePlugin
from leetha.probe.plugins.synology import SynologyProbePlugin
from leetha.probe.plugins.syslog_probe import SyslogProbePlugin
from leetha.probe.plugins.tacacs import TACACSProbePlugin
from leetha.probe.plugins.tango import TANGOProbePlugin
from leetha.probe.plugins.taxii import TAXIIProbePlugin
from leetha.probe.plugins.teamspeak import TeamSpeakProbePlugin
from leetha.probe.plugins.teamviewer import TeamViewerProbePlugin
from leetha.probe.plugins.telnet import TelnetProbePlugin
from leetha.probe.plugins.tftp import TFTPProbePlugin
from leetha.probe.plugins.tidb import TiDBProbePlugin
from leetha.probe.plugins.tinc import TincProbePlugin
from leetha.probe.plugins.tn3270 import TN3270ProbePlugin
from leetha.probe.plugins.tn5250 import TN5250ProbePlugin
from leetha.probe.plugins.tplink import TPLinkProbePlugin
from leetha.probe.plugins.traefik_api import TraefikAPIProbePlugin
from leetha.probe.plugins.triton import TritonProbePlugin
from leetha.probe.plugins.truenas import TrueNASProbePlugin
from leetha.probe.plugins.tuya import TuyaProbePlugin
from leetha.probe.plugins.unifi import UniFiProbePlugin
from leetha.probe.plugins.unraid import UnraidProbePlugin
from leetha.probe.plugins.vault import VaultProbePlugin
from leetha.probe.plugins.veeam import VeeamProbePlugin
from leetha.probe.plugins.virtualbox_web import VirtualBoxWebProbePlugin
from leetha.probe.plugins.vllm import VllmProbePlugin
from leetha.probe.plugins.visa import VISAProbePlugin
from leetha.probe.plugins.vmware_esxi import VMwareESXiProbePlugin
from leetha.probe.plugins.vnc import VNCProbePlugin
from leetha.probe.plugins.vtam import VTAMProbePlugin
from leetha.probe.plugins.weaviate import WeaviateProbePlugin
from leetha.probe.plugins.webdav import WebDAVProbePlugin
from leetha.probe.plugins.webmin import WebminProbePlugin
from leetha.probe.plugins.websocket import WebSocketProbePlugin
from leetha.probe.plugins.whois import WHOISProbePlugin
from leetha.probe.plugins.winrm import WinRMProbePlugin
from leetha.probe.plugins.wireguard import WireGuardProbePlugin
from leetha.probe.plugins.x11 import X11ProbePlugin
from leetha.probe.plugins.xdmcp import XDMCPProbePlugin
from leetha.probe.plugins.xds import XDSProbePlugin
from leetha.probe.plugins.xenserver import XenServerProbePlugin
from leetha.probe.plugins.xmpp import XMPPProbePlugin
from leetha.probe.plugins.xnat import XNATProbePlugin
from leetha.probe.plugins.yarn import YARNProbePlugin
from leetha.probe.plugins.zerotier import ZeroTierProbePlugin
from leetha.probe.plugins.zookeeper import ZooKeeperProbePlugin

PLUGINS = [
    ACMEProbePlugin,
    ActiveMQProbePlugin,
    AETitleProbePlugin,
    AFPProbePlugin,
    AirPlayProbePlugin,
    AMQPProbePlugin,
    AnyConnectProbePlugin,
    AnyDeskProbePlugin,
    ArangoDBProbePlugin,
    ArgoCDProbePlugin,
    ArtifactoryProbePlugin,
    ArubaProbePlugin,
    ASTERIXProbePlugin,
    ATGProbePlugin,
    BACnetProbePlugin,
    BeeGFSProbePlugin,
    BGPProbePlugin,
    BoundaryProbePlugin,
    CalicoProbePlugin,
    CANopenProbePlugin,
    CASProbePlugin,
    CassandraProbePlugin,
    CephProbePlugin,
    ChromaDBProbePlugin,
    CICSProbePlugin,
    CIFSProbePlugin,
    CiliumProbePlugin,
    CiscoSmartInstallProbePlugin,
    ClickHouseProbePlugin,
    CoAPProbePlugin,
    CockpitProbePlugin,
    CockroachDBProbePlugin,
    CodesysProbePlugin,
    CondorProbePlugin,
    ConjurProbePlugin,
    ConsulProbePlugin,
    ContainerdProbePlugin,
    CouchDBProbePlugin,
    CrimsonV3ProbePlugin,
    DaskProbePlugin,
    DB2ProbePlugin,
    DDSProbePlugin,
    DiameterProbePlugin,
    DICOMProbePlugin,
    DLNAProbePlugin,
    DNP3ProbePlugin,
    DNSProbePlugin,
    DockerAPIProbePlugin,
    DockerRegistryProbePlugin,
    DovecotProbePlugin,
    DRDAProbePlugin,
    ElasticsearchProbePlugin,
    EmbyProbePlugin,
    ENIPProbePlugin,
    EnvoyAdminProbePlugin,
    EPICSProbePlugin,
    EtcdProbePlugin,
    EtherCATProbePlugin,
    FFHSEProbePlugin,
    FHIRProbePlugin,
    FingerProbePlugin,
    FINSProbePlugin,
    FirebirdProbePlugin,
    FissionProbePlugin,
    FluentdProbePlugin,
    FortiGateProbePlugin,
    FoxProbePlugin,
    FreeIPAProbePlugin,
    FTPProbePlugin,
    GESRTPProbePlugin,
    GitProtoProbePlugin,
    GitLabProbePlugin,
    GradioProbePlugin,
    GlobalProtectProbePlugin,
    GlobusProbePlugin,
    GlusterFSProbePlugin,
    GoogleCastProbePlugin,
    GopherProbePlugin,
    GPFSProbePlugin,
    GrafanaProbePlugin,
    GraphiteProbePlugin,
    GraphQLProbePlugin,
    GraylogGELFProbePlugin,
    GRPCProbePlugin,
    GTPProbePlugin,
    H323ProbePlugin,
    HadoopNameNodeProbePlugin,
    HAProxyStatsProbePlugin,
    HarborProbePlugin,
    HARTIPProbePlugin,
    HBaseProbePlugin,
    HikvisionProbePlugin,
    HL7MLLPProbePlugin,
    HLSProbePlugin,
    HomeAssistantProbePlugin,
    HomeKitProbePlugin,
    HuggingFaceTGIProbePlugin,
    HTTPProbePlugin,
    HTTPProxyProbePlugin,
    HueBridgeProbePlugin,
    HyperVProbePlugin,
    IAX2ProbePlugin,
    IcecastProbePlugin,
    IEC104ProbePlugin,
    IEC61850ProbePlugin,
    IKEProbePlugin,
    IMAPProbePlugin,
    IMSConnectProbePlugin,
    InfluxDBProbePlugin,
    IOLinkProbePlugin,
    IPFIXProbePlugin,
    IPMIProbePlugin,
    IPPProbePlugin,
    IRCProbePlugin,
    ISCSIProbePlugin,
    JDWPProbePlugin,
    JenkinsProbePlugin,
    JetDirectProbePlugin,
    JMXProbePlugin,
    JREAPProbePlugin,
    K3sProbePlugin,
    KafkaProbePlugin,
    KerberosProbePlugin,
    KeycloakProbePlugin,
    KibanaProbePlugin,
    KnativeProbePlugin,
    KNXIPProbePlugin,
    KongProbePlugin,
    KubernetesAPIProbePlugin,
    L2TPProbePlugin,
    LDAPProbePlugin,
    LibvirtProbePlugin,
    Link16ProbePlugin,
    LinkerdProbePlugin,
    LiteLLMProbePlugin,
    LLMNRProbePlugin,
    LMTPProbePlugin,
    LPDProbePlugin,
    LustreProbePlugin,
    LwM2MProbePlugin,
    LXIProbePlugin,
    ManageSieveProbePlugin,
    MatrixProbePlugin,
    MattermostProbePlugin,
    MDNSProbePlugin,
    MELSECProbePlugin,
    MemcachedProbePlugin,
    MGCPProbePlugin,
    MikroTikProbePlugin,
    MilterProbePlugin,
    MinIOProbePlugin,
    ModbusProbePlugin,
    ModbusRTUProbePlugin,
    MongoDBProbePlugin,
    MPDProbePlugin,
    MPIProbePlugin,
    MQSeriesProbePlugin,
    MQTTProbePlugin,
    MSSQLProbePlugin,
    MumbleProbePlugin,
    MySQLProbePlugin,
    NATOMIPProbePlugin,
    NATSProbePlugin,
    NDMPProbePlugin,
    Neo4jProbePlugin,
    NetBIOSProbePlugin,
    NexusProbePlugin,
    NexusRMProbePlugin,
    NFSProbePlugin,
    NNTPProbePlugin,
    NomadProbePlugin,
    NRPEProbePlugin,
    NTLMProbePlugin,
    NTPProbePlugin,
    NuclioProbePlugin,
    NutanixProbePlugin,
    NXProbePlugin,
    OAuth2ProbePlugin,
    OllamaProbePlugin,
    ONVIFProbePlugin,
    OPCDAProbePlugin,
    OPCUAProbePlugin,
    OpenAICompatProbePlugin,
    OpenFaaSProbePlugin,
    OpenHABProbePlugin,
    OpenShiftProbePlugin,
    OpenVPNProbePlugin,
    OpenWhiskProbePlugin,
    OpenWrtProbePlugin,
    OracleTNSProbePlugin,
    OTLPProbePlugin,
    OvirtProbePlugin,
    PACSProbePlugin,
    PBSProbePlugin,
    PCOMProbePlugin,
    PCWorxProbePlugin,
    PerforceProbePlugin,
    PfSenseProbePlugin,
    PgAdminProbePlugin,
    PhpMyAdminProbePlugin,
    PlexProbePlugin,
    PodmanProbePlugin,
    POP3ProbePlugin,
    PortainerProbePlugin,
    PostgreSQLProbePlugin,
    PPTPProbePlugin,
    ProConOSProbePlugin,
    PROFINETProbePlugin,
    PrometheusProbePlugin,
    ProxmoxVEProbePlugin,
    PulsarProbePlugin,
    PuppetProbePlugin,
    QNAPProbePlugin,
    QuayProbePlugin,
    RabbitMQProbePlugin,
    RADIUSProbePlugin,
    RancherProbePlugin,
    RayProbePlugin,
    RDPProbePlugin,
    REDCapProbePlugin,
    RedisProbePlugin,
    RloginProbePlugin,
    RMIProbePlugin,
    RokuECPProbePlugin,
    RSHProbePlugin,
    RspamdProbePlugin,
    RsyncProbePlugin,
    RTMPProbePlugin,
    RTSPProbePlugin,
    RtspProbePlugin,
    RuckusProbePlugin,
    S3CompatProbePlugin,
    S7commProbePlugin,
    SaltProbePlugin,
    SAMLProbePlugin,
    SANEProbePlugin,
    SAPDiagProbePlugin,
    SAPRouterProbePlugin,
    SCPIRawProbePlugin,
    SCTPTestProbePlugin,
    ScyllaDBProbePlugin,
    SFlowProbePlugin,
    SGEProbePlugin,
    ShellyProbePlugin,
    SHOUTcastProbePlugin,
    SIPProbePlugin,
    SlurmProbePlugin,
    SMBProbePlugin,
    SMPPProbePlugin,
    SMTPProbePlugin,
    SNMPProbePlugin,
    SOCKS4ProbePlugin,
    SOCKS5ProbePlugin,
    SoftEtherProbePlugin,
    SonarQubeProbePlugin,
    SonosProbePlugin,
    SparkMasterProbePlugin,
    SPIFFEProbePlugin,
    SplunkHECProbePlugin,
    SSDPProbePlugin,
    SSHProbePlugin,
    StableDiffusionProbePlugin,
    SSTPProbePlugin,
    STANAG4586ProbePlugin,
    StatsDProbePlugin,
    StepCAProbePlugin,
    STOMPProbePlugin,
    STUNProbePlugin,
    SubmissionProbePlugin,
    SVNProbePlugin,
    SwiftStorageProbePlugin,
    SynologyProbePlugin,
    SyslogProbePlugin,
    TACACSProbePlugin,
    TANGOProbePlugin,
    TAXIIProbePlugin,
    TeamSpeakProbePlugin,
    TeamViewerProbePlugin,
    TelnetProbePlugin,
    TFTPProbePlugin,
    TiDBProbePlugin,
    TincProbePlugin,
    TN3270ProbePlugin,
    TN5250ProbePlugin,
    TPLinkProbePlugin,
    TraefikAPIProbePlugin,
    TritonProbePlugin,
    TrueNASProbePlugin,
    TuyaProbePlugin,
    UniFiProbePlugin,
    UnraidProbePlugin,
    VaultProbePlugin,
    VeeamProbePlugin,
    VirtualBoxWebProbePlugin,
    VISAProbePlugin,
    VllmProbePlugin,
    VMwareESXiProbePlugin,
    VNCProbePlugin,
    VTAMProbePlugin,
    WeaviateProbePlugin,
    WebDAVProbePlugin,
    WebminProbePlugin,
    WebSocketProbePlugin,
    WHOISProbePlugin,
    WinRMProbePlugin,
    WireGuardProbePlugin,
    X11ProbePlugin,
    XDMCPProbePlugin,
    XDSProbePlugin,
    XenServerProbePlugin,
    XMPPProbePlugin,
    XNATProbePlugin,
    YARNProbePlugin,
    ZeroTierProbePlugin,
    ZooKeeperProbePlugin,
]
