package ast

type Node struct {
	Key      int
	Value    NodeValue
	Children []*Node
}

func (n *Node) Search(key int) (*Node, bool) {
	for _, child := range n.Children {
		if child.Key == key {
			return child, true
		} else if child.Key > key {
			return child.Search(key)
		}
	}
	return nil, false
}

func (n *Node) Insert(key int, Tagname *string, Content *string, Attributes *[]*Attribute) {
	if n.Length() != 0 {
		for _, child := range n.Children {
			if child.Key > key {
				child.Insert(key, Tagname, Content, Attributes)
				return
			}
		}
	}
	n.Children = append(n.Children, &Node{Key: key, Value: NodeValue{Tagname: *Tagname, Content: *Content, Attributes: *Attributes}})
}

func (n *Node) Delete(key int) bool {
	for i, child := range n.Children {
		if child.Key == key {
			n.Children = append(n.Children[:i], n.Children[i+1:]...)
			return true
		} else if child.Key > key {
			return child.Delete(key)
		}
	}
	return false
}

func (n *Node) Max() (*Node, bool) {
	maxkey := n.Key

	for _, child := range n.Children {
		if child.Key > maxkey {
			maxkey = child.Key
		}
	}
	maxnode, b := n.Search(maxkey)
	if !b {
		return nil, false
	}
	return maxnode, true
}

func (n *Node) Set(node *Node) {
	n.Insert(node.Key, &node.Value.Tagname, &node.Value.Content, &node.Value.Attributes)
}

func (n *Node) Length() int {
	return len(n.Children)
}

func (n *Node) Clear() {
	n.Children = n.Children[:0]
	n.Key = 0
	n.Value = NodeValue{}
}
