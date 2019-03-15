require 'linux/netlink/route'
require 'linux/netlink/route/handler'

module Linux
  module Netlink
    module Route
      NDCacheInfo = Struct.new :confirmed, :used, :updated, :refcnt

      class ND < RtattrMessage
        code RTM_NEWNEIGH, RTM_DELNEIGH, RTM_GETNEIGH
        field :family, :uchar
        field :pad1, :uchar
        field :pad2, :uint16
        field :iface, :int32
        field :state, :uint16
        field :flags, :uchar
        field :type, :uchar
        rtattr :dst, NDA_DST, :l3addr
        rtattr :lladdr, NDA_LLADDR, :l2addr
        rtattr :cacheinfo, NDA_CACHEINFO,
               :pack   => lambda { |val,obj| val.to_a.pack("L*") },
               :unpack => lambda { |str,obj| NDCacheInfo.new(*(str.unpack("L*"))) }
        rtattr :probes, NDA_PROBES, :uint32
      # 	NDA_PROBES,
      # 	NDA_VLAN,
      # 	NDA_PORT,
      # 	NDA_VNI,
      # 	NDA_IFINDEX,
      # 	NDA_MASTER,
      # 	NDA_LINK_NETNSID,
      # 	NDA_SRC_VNI,
      end


      class NeighborHandler < Handler

        def clear_cache
          @neigh = nil
        end
        
        def read_neigh(opt=nil, &blk)
          @rtsocket.send_request RTM_GETNEIGH, ND.new(opt),
                                 NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST
          @rtsocket.receive_until_done(RTM_NEWNEIGH, &blk)
        end

        class Filter < BaseFilter #:nodoc:
          filter(:family) { |o,v| o.family == v }
          filter(:type) { |o,v| o.type == v }
          filter(:flags) { |o,v| (o.flags & v) == v }
          filter(:noflags) { |o,v| (o.flags & v) == 0 }
          filter(:iface) { |o,v| o.iface == v }
        end

        def list(filter=nil, &blk)
          @neigh ||= read_neigh
          filter[:iface] = index(filter[:iface]) if filter && filter.has_key?(:iface)
          filter_list(@neigh, filter, &blk)
        end
        alias :each :list

        def add(opt)
          ipneigh_modify(RTM_NEWNEIGH, NLM_F_CREATE|NLM_F_EXCL, opt)
        end

        def change(opt)
          ipneigh_modify(RTM_NEWNEIGH, NLM_F_REPLACE, opt)
        end

        def replace(opt)
          ipneigh_modify(RTM_NEWNEIGH, NLM_F_CREATE|NLM_F_REPLACE, opt)
        end

        def delete(opt)
          ipneigh_modify(RTM_DELNEIGH, 0, opt)
        end

        def ipneigh_modify(code, flags, msg) #:nodoc:
          msg = ND.new(msg)
          msg.iface = index(msg.iface) if msg.iface.is_a?(String)
          @rtsocket.cmd code, msg, flags|NLM_F_REQUEST
          clear_cache
        end
      end
    end
  end
end